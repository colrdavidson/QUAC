#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/core_names.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>

#define panicf(...) do { printf(__VA_ARGS__); __builtin_debugtrap(); } while (0)
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ELEM_COUNT(arr) (sizeof(arr) / sizeof((arr)[0]))

void dump_bytes_width(uint8_t *bytes, size_t len, int width) {
	for (int i = 0; i < len; i++) {
		printf("%02x", bytes[i]);
		if (i + 1 < len) {
			printf(" ");
		}
		if (i + 1 == len || (i > 0 && (i + 1) % width == 0)) {
			printf("\n");
		}
	}
}

void dump_bytes(uint8_t *bytes, size_t len) {
	dump_bytes_width(bytes, len, 25);
}

void dump_flat_bytes(uint8_t *bytes, size_t len) {
	for (int i = 0; i < len; i++) {
		printf("%02x", bytes[i]);
		if (i + 1 == len) {
			printf(" ");
		}
	}
}

typedef enum {
	Message_Failed     = 0,
	Message_Success    = 1,
	Message_Fragmented = 2,
} Message_State;

#include "slice.h"
#include "crypto.h"
#include "tls.h"

uint8_t initial_salt[] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d,
	0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
	0x7f, 0x0a
};

uint8_t empty_sha256_hash[32] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a,
	0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae,
	0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99,
	0x1b, 0x78, 0x52, 0xb8, 0x55
};

#define QUIC_PACKET_LONGTYPE(X) \
	X(LongType_Initial,    0)   \
	X(LongType_0RTT,       1)   \
	X(LongType_Handshake,  2)   \
	X(LongType_Retry,      3)

#define QUIC_FRAME_TYPE(X)              \
	X(Frame_Padding,              0x00) \
	X(Frame_Ping,                 0x01) \
	X(Frame_Ack1,                 0x02) \
	X(Frame_Ack2,                 0x03) \
	X(Frame_ResetStream,          0x04) \
	X(Frame_StopSending,          0x05) \
	X(Frame_Crypto,               0x06) \
	X(Frame_NewToken,             0x07) \
	X(Frame_Stream1,              0x08) \
	X(Frame_Stream2,              0x09) \
	X(Frame_Stream3,              0x0a) \
	X(Frame_Stream4,              0x0b) \
	X(Frame_Stream5,              0x0c) \
	X(Frame_Stream6,              0x0d) \
	X(Frame_Stream7,              0x0e) \
	X(Frame_Stream8,              0x0f) \
	X(Frame_MaxData,              0x10) \
	X(Frame_MaxStreamData,        0x11) \
	X(Frame_MaxStreams1,          0x12) \
	X(Frame_MaxStreams2,          0x13) \
	X(Frame_DataBlocked,          0x14) \
	X(Frame_StreamDataBlocked,    0x15) \
	X(Frame_StreamsBlocked1,      0x16) \
	X(Frame_StreamsBlocked2,      0x17) \
	X(Frame_NewConnectionID,      0x18) \
	X(Frame_RetireConnectionID,   0x19) \
	X(Frame_PathChallenge,        0x1a) \
	X(Frame_PathResponse,         0x1b) \
	X(Frame_ConnectionClose_QUIC, 0x1c) \
	X(Frame_ConnectionClose_App,  0x1d) \
	X(Frame_HandshakeDone,        0x1e)

#define X(name, val) name = val,
typedef enum {
	QUIC_FRAME_TYPE(X)
} QUIC_Frame_Type;

typedef enum {
	QUIC_PACKET_LONGTYPE(X)
} QUIC_Packet_LongType;
#undef X

#define X(name, val) case name: return #name;
char *quic_frame_type_to_str(QUIC_Frame_Type x) {
	switch (x) {
		QUIC_FRAME_TYPE(X)
		default: return "(unknown)";
	}
}
char *quic_packet_longtype_to_str(QUIC_Packet_LongType x) {
	switch (x) {
		QUIC_PACKET_LONGTYPE(X)
		default: return "(unknown)";
	}
}
#undef X

typedef struct {
	char *hostname;
	uint64_t hostname_len;

	uint8_t *src_id;
	uint64_t src_id_len;

	uint8_t *dst_id;
	uint64_t dst_id_len;

	uint8_t client_rand[32];
	uint8_t server_rand[32];

	uint8_t client_private_key[32];
	uint8_t client_public_key[32];

	uint8_t server_public_key[32];

	uint8_t initial_secret[32];

	uint8_t client_secret[32];
	uint8_t client_key[16];
	uint8_t client_iv[12];
	uint8_t client_hp[16];

	uint8_t server_secret[32];
	uint8_t server_key[16];
	uint8_t server_iv[12];
	uint8_t server_hp[16];

	EVP_MD_CTX *mdctx;
	uint8_t hello_hash[32];

	uint8_t client_handshake_key[16];
	uint8_t client_handshake_iv[12];
	uint8_t client_handshake_hp[16];

	uint8_t server_handshake_key[16];
	uint8_t server_handshake_iv[12];
	uint8_t server_handshake_hp[16];

	QUIC_Transport_Params params;

	TLS_State tls;
} Conn_Info;

bool gen_initial_keys(Conn_Info *ci_out, char *hostname, uint8_t *dst_id, int dst_id_len, uint8_t *src_id, int src_id_len) {
	Conn_Info ci = {};

	ci.dst_id = dst_id;
	ci.dst_id_len = dst_id_len;

	ci.src_id = src_id;
	ci.src_id_len = src_id_len;

	ci.hostname = hostname;
	ci.hostname_len = strlen(hostname);

	for (int i = 0; i < sizeof(ci.client_rand); i++) {
		ci.client_rand[i] = i;
	}
	for (int i = 0; i < 32; i++) {
		ci.client_private_key[i] = i + 0x20;
	}
	generate_public_key(ci.client_private_key, ci.client_public_key);

	uint8_t initial_rand[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

	char client_secret_label[] = "client in";
	char server_secret_label[] = "server in";
	char key_label[]           = "quic key";
	char iv_label[]            = "quic iv";
	char hp_label[]            = "quic hp";

	hdkf_extract(ci.initial_secret, initial_salt, sizeof(initial_salt), initial_rand, sizeof(initial_rand));

	hdkf_expand_label(ci.client_secret, sizeof(ci.client_secret), ci.initial_secret, client_secret_label);
	hdkf_expand_label(ci.client_key,    sizeof(ci.client_key),    ci.client_secret,  key_label);
	hdkf_expand_label(ci.client_iv,     sizeof(ci.client_iv),     ci.client_secret,  iv_label);
	hdkf_expand_label(ci.client_hp,     sizeof(ci.client_hp),     ci.client_secret,  hp_label);

	hdkf_expand_label(ci.server_secret, sizeof(ci.server_secret), ci.initial_secret, server_secret_label);
	hdkf_expand_label(ci.server_key,    sizeof(ci.server_key),    ci.server_secret,  key_label);
	hdkf_expand_label(ci.server_iv,     sizeof(ci.server_iv),     ci.server_secret,  iv_label);
	hdkf_expand_label(ci.server_hp,     sizeof(ci.server_hp),     ci.server_secret,  hp_label);

	ci.mdctx = init_sha256();

	*ci_out = ci;
	return true;
}

bool gen_handshake_keys(Conn_Info *ci) {
	finish_sha256_sum(ci->mdctx, ci->hello_hash);

	uint8_t zero_key[32] = {};
	uint8_t blank_salt[1] = {};

	uint8_t early_secret[32];
	uint8_t derived_secret[32];
	uint8_t shared_secret[32];
	uint8_t handshake_secret[32];

	uint8_t client_secret[32];
	uint8_t server_secret[32];

	char derived_label[]       = "derived";
	char client_secret_label[] = "c hs traffic";
	char server_secret_label[] = "s hs traffic";
	char key_label[]           = "quic key";
	char iv_label[]            = "quic iv";
	char hp_label[]            = "quic hp";

	hdkf_extract(early_secret, blank_salt, sizeof(blank_salt), zero_key, sizeof(zero_key));
	hdkf_expand_label_with_extra(derived_secret, sizeof(derived_secret), early_secret, empty_sha256_hash, sizeof(empty_sha256_hash), derived_label);

	generate_shared_secret(ci->client_private_key, ci->server_public_key, shared_secret);
	hdkf_extract(handshake_secret, derived_secret, sizeof(derived_secret), shared_secret, sizeof(shared_secret));

	hdkf_expand_label_with_extra(client_secret, sizeof(client_secret), handshake_secret, ci->hello_hash, sizeof(ci->hello_hash), client_secret_label);
/*
	printf("CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
	dump_flat_bytes(ci->client_rand, sizeof(ci->client_rand));
	dump_flat_bytes(client_secret, sizeof(client_secret));
	printf("\n");
*/

	hdkf_expand_label(ci->client_handshake_key, sizeof(ci->client_handshake_key), client_secret, key_label);
	hdkf_expand_label(ci->client_handshake_iv,  sizeof(ci->client_handshake_iv),  client_secret, iv_label);
	hdkf_expand_label(ci->client_handshake_hp,  sizeof(ci->client_handshake_hp),  client_secret, hp_label);

	hdkf_expand_label_with_extra(server_secret, sizeof(server_secret), handshake_secret, ci->hello_hash, sizeof(ci->hello_hash), server_secret_label);
/*
	printf("SERVER_HANDSHAKE_TRAFFIC_SECRET ");
	dump_flat_bytes(ci->client_rand, sizeof(ci->client_rand));
	dump_flat_bytes(server_secret, sizeof(server_secret));
	printf("\n");
*/

	hdkf_expand_label(ci->server_handshake_key, sizeof(ci->server_handshake_key), server_secret, key_label);
	hdkf_expand_label(ci->server_handshake_iv,  sizeof(ci->server_handshake_iv),  server_secret, iv_label);
	hdkf_expand_label(ci->server_handshake_hp,  sizeof(ci->server_handshake_hp),  server_secret, hp_label);
	
	return true;
}

int build_initial_packet(Conn_Info *ci, uint8_t *buffer, size_t buffer_size) {
	if (buffer_size < 1200) { return 0; }

	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	// Build TLS Client Hello
	uint8_t client_hello[1500] = {};
	int64_t client_hello_size = build_client_hello(
		client_hello, sizeof(client_hello),
		ci->hostname, ci->hostname_len,
		ci->client_rand, sizeof(ci->client_rand),
		ci->client_public_key, sizeof(ci->client_public_key),
		ci->src_id, ci->src_id_len,
		&ci->params
	);
	update_sha256_sum(ci->mdctx, client_hello, client_hello_size);

	uint8_t pkt_hdr_byte = 0;
	pkt_hdr_byte |= 1 << 7; // form
	pkt_hdr_byte |= 1 << 6; // fixed
	pkt_hdr_byte |= 0 << 4; // type
	pkt_hdr_byte |= 0 << 2; // reserved
	pkt_hdr_byte |= 0 << 0; // packet num length

	// Packet Header
	write_u8(&s, pkt_hdr_byte);

	// Packet Version
	write_u32_be(&s, 0x1);

	// Destination ID
	write_u8(&s, ci->dst_id_len);
	write_data(&s, ci->dst_id, ci->dst_id_len);

	// Source ID
	write_u8(&s, ci->src_id_len);
	write_data(&s, ci->src_id, ci->src_id_len);

	// Token -- no token present
	write_u8(&s, 0);

	uint8_t crypto_frame[1600] = {};
	Slice cf = { .data = crypto_frame, .len = 0, .cap = sizeof(crypto_frame) };
	write_u8(&cf, 0x6);
	write_varint(&cf, 0);
	write_varint(&cf, client_hello_size);
	write_data(&cf, client_hello, client_hello_size);
	int aead_len = 16;

	uint64_t packet_len = 1 + cf.len + aead_len;
	write_varint(&s, packet_len);

	// Packet Number
	uint64_t pkt_num = 0;
	uint64_t pkt_num_start = s.len;
	write_u8(&s, pkt_num);

	uint8_t *pkt_hdr = s.data;
	uint64_t pkt_hdr_size = s.len;

	// Add encrypted payload
	uint8_t encrypted_data[1600] = {};
	uint8_t aead_bytes[16] = {};
	encrypt_buffer(encrypted_data,
		cf.data, cf.len,
		ci->client_key, ci->client_iv, pkt_num, aead_bytes, pkt_hdr, pkt_hdr_size
	);
	write_data(&s, encrypted_data, cf.len);
	write_data(&s, aead_bytes, aead_len);

	// Generate payload mask for header protection
	uint8_t payload_mask[16] = {};
	uint8_t *sample = s.data + pkt_num_start + 4;
	generate_mask(payload_mask, sample, ci->client_hp);

	// add header protection to second half of header byte
	s.data[0] = s.data[0] ^ (payload_mask[0] & 0x0F);

	// add header protection to packet number
	for (int i = 0; i < 1; i++) {
		*(s.data + pkt_num_start + i) ^= payload_mask[i+1];
	}

	return 1200;
}

int decode_server_packet(Conn_Info *ci, uint8_t *buffer, size_t buffer_size, uint8_t *plaintext_buffer, uint64_t *plaintext_size) {
	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	uint8_t pkt_hdr_byte = read_u8(&s);
	bool is_long      = (pkt_hdr_byte & 0x80) >> 7;
	uint8_t fixed_bit = (pkt_hdr_byte & 0x40) >> 6;
	uint8_t pkt_type  = (pkt_hdr_byte & 0x30) >> 4;

	printf("pkt %x | is long: %u, fixed: %u, type: (%u) %s\n", pkt_hdr_byte, is_long, fixed_bit, pkt_type, quic_packet_longtype_to_str(pkt_type));

	if (is_long != true) {
		panicf("TODO: handle short packets!\n");
	}

	uint8_t payload_mask[16] = {};
	uint64_t pkt_len = 0;

	uint8_t *server_hp;
	uint8_t *server_key;
	uint8_t *server_iv;

	uint32_t quic_version = read_u32_be(&s);

	uint8_t dst_id_len = read_u8(&s);
	uint8_t *dst_id = read_data(&s, dst_id_len);

	uint8_t src_id_len = read_u8(&s);
	uint8_t *src_id = read_data(&s, src_id_len);

	switch ((QUIC_Packet_LongType)pkt_type) {
		case LongType_Initial: {
			// Skip token
			uint8_t token = read_u8(&s);

			pkt_len = read_varint(&s);

			server_hp  = ci->server_hp;
			server_key = ci->server_key;
			server_iv  = ci->server_iv;
		} break;
		case LongType_Handshake: {
			pkt_len = read_varint(&s);

			server_hp  = ci->server_handshake_hp;
			server_key = ci->server_handshake_key;
			server_iv  = ci->server_handshake_iv;
		} break;
		default: {
			printf("unhandled packet type (hdr: %x) %s\n", pkt_hdr_byte, quic_packet_longtype_to_str(pkt_type));
			return 0;
		}
	}

	uint8_t *sample = s.data + s.len + 4;
	generate_mask(payload_mask, sample, server_hp);

	// unprotect packet header
	s.data[0] = s.data[0] ^ (payload_mask[0] & 0x0F);
	pkt_hdr_byte = s.data[0];

	uint64_t pkt_num_len = ((uint64_t)1ull) << (pkt_hdr_byte & 0x03);
	uint64_t pkt_num_start = s.len;

	// unprotect packet number
	for (int i = 0; i < pkt_num_len; i++) {
		*(s.data + pkt_num_start + i) ^= payload_mask[i+1];
	}
	uint64_t pkt_num = read_varint_len(&s, pkt_num_len);

	uint8_t *pkt_hdr = s.data;
	uint64_t pkt_hdr_size = s.len;

	uint64_t aead_len = 16;
	uint64_t encrypted_size = pkt_len - pkt_num_len - aead_len;
	uint8_t *encrypted_buffer = read_data(&s, encrypted_size);

	uint8_t *aead = read_data(&s, aead_len);

	if (!decrypt_buffer(plaintext_buffer, encrypted_buffer, encrypted_size, server_key, server_iv, pkt_num, aead, pkt_hdr, pkt_hdr_size)) {
		printf("failed to decrypt server packet!\n");
		return 0;
	}

	*plaintext_size = encrypted_size;
	return s.len;
}

Message_State parse_server_frames(Conn_Info *ci, uint8_t *buffer, size_t buffer_size) {
	Slice pt = {.data = buffer, .len = 0, .cap = buffer_size};

	while (pt.len < pt.cap) {
		uint8_t frame_type_byte = read_u8(&pt);
		QUIC_Frame_Type frame_type = (QUIC_Frame_Type)frame_type_byte;
		switch (frame_type) {
			case Frame_ConnectionClose_QUIC: {
				printf("Connection closed?\n");
				printf("data remaining in packet:\n"); dump_bytes(pt.data + pt.len, pt.cap - pt.len);

				uint64_t error_code = read_varint(&pt);
				uint64_t frame_type = read_varint(&pt);
				uint64_t reason_phrase_len = read_varint(&pt);

				printf("error code: 0x%llx, frame type: (%llx) %s, reason phrase len: 0x%02llx\n", error_code, frame_type, quic_frame_type_to_str(frame_type), reason_phrase_len);
				if (error_code >= 0x100 && error_code <= 0x1FF) {
					TLS_Alert_Desc alert_code = (TLS_Alert_Desc)error_code - 0x100;
					printf("CRYPTO ERROR! %d || %s\n", alert_code, tls_alert_desc_to_str(alert_code));
				}

				return Message_Failed;
			} break;
			case Frame_Ack1: {
				uint8_t largest_ack = read_u8(&pt);
				uint64_t ack_delay = read_varint(&pt);
				uint8_t ack_range_count = read_u8(&pt);
				uint64_t first_ack_range = read_varint(&pt);
			} break;
			case Frame_Crypto: {
				uint64_t offset = read_varint(&pt);
				uint64_t size   = read_varint(&pt);
				uint8_t *data = read_data(&pt, size);
				printf("crypto frame off: %llu, size: %llu\n", offset, size);

				switch (ci->tls.state) {
					case TLS_State_Initial: {
						Message_State state = tls_initial(&ci->tls, data, size, ci->mdctx, ci->server_public_key, sizeof(ci->server_public_key), ci->server_rand);
						if (state != Message_Success) { return state; }

						gen_handshake_keys(ci);
						ci->tls.state = TLS_State_Handshake;
					} break;
					case TLS_State_Handshake: {
						Message_State state = tls_handshake(&ci->tls, data, size, &ci->params);
						if (state != Message_Success) { return state; }
					} break;
				}
			} break;
			default: {
				printf("Unhandled frame type: (0x%x) %s\n", frame_type, quic_frame_type_to_str(frame_type));
				return Message_Failed;
			}
		}
	}

	return Message_Success;
}


int main() {
	int sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd == -1) { return 1; }

	int opt = 0;
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
		printf("unable to set up IPv6/IPv4 dual stack!\n");
		return 1;
	}

	int16_t port = 443;

	struct sockaddr_in6 srv_addr = {};
	srv_addr.sin6_family = AF_INET6;
	srv_addr.sin6_port   = htons(port);
	if (inet_pton(AF_INET6, "::1", &srv_addr.sin6_addr) < 0) {
		printf("failed to set addr\n");
		return 1;
	}

	struct sockaddr_in6 client_addr = {};
	socklen_t addr_len = sizeof(client_addr);

	uint8_t dst_id[8] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
	int dst_id_len = sizeof(dst_id);

	uint8_t src_id[] = "c_cid";
	int src_id_len = sizeof(src_id) - 1;

	Conn_Info ci;
	if (!gen_initial_keys(&ci, "localhost", dst_id, dst_id_len, src_id, src_id_len)) {
		printf("failed to init connection!\n");
		return 1;
	}

	uint8_t send_buffer[1500] = {};
	int pkt_size = build_initial_packet(&ci, send_buffer, sizeof(send_buffer));

	ssize_t sent_bytes = sendto(sd, send_buffer, pkt_size, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (sent_bytes < 0) {
		printf("failed to send to server!\n");
		return 1;
	}
	printf("sent to server!\n");

	uint8_t recv_buffer[1500] = {};

	Message_State state = Message_Failed;
	do {
		ssize_t recv_bytes = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
		if (recv_bytes < 0) {
			printf("failed to get response from server!\n");
			return 1;
		}
		printf("got %zd byte response!\n", recv_bytes);

		int proc_size = 0;

		uint8_t plaintext_buffer[1500] = {};
		uint64_t plaintext_size = 0;
		while (proc_size < recv_bytes) {
			int ret = decode_server_packet(&ci, recv_buffer + proc_size, recv_bytes - proc_size, plaintext_buffer, &plaintext_size);
			if (ret == 0) {
				printf("failed to decode server packet!\n");
				return 1;
			}
			printf("decoded %d QUIC bytes\n", ret);

			state = parse_server_frames(&ci, plaintext_buffer, plaintext_size);
			if (state == Message_Failed) {
				printf("failed to process server frames!\n");
				return 1;
			}

			proc_size += ret;
		}
	} while (state == Message_Fragmented);

	close(sd);
	return 0;
}
