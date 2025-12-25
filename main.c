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

#define DEBUG_DUMP false

#define panicf(...) do { printf(__VA_ARGS__); __builtin_debugtrap(); } while (0)
#define BOOL_STR_CUSTOM(x, t, f) ((x) ? (t) : (f))
#define BOOL_STR(x) BOOL_STR_CUSTOM((x), "true", "false")
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
	uint64_t id;
	uint64_t offset;
	bool is_open;
	bool is_client_initiated;
	bool is_bidirectional;

	bool is_crypto;
} QUIC_Stream;

typedef struct {
	uint64_t    key;
	QUIC_Stream val;
} Stream_Entry;

typedef struct {
	uint64_t entries_cap;
	uint64_t entries_len;
	Stream_Entry *entries;

	uint64_t hashes_cap;
	int64_t *hashes;
} Stream_Map;

typedef struct {
	char *hostname;
	char *protocol;

	uint8_t *src_id;
	uint64_t src_id_len;

	uint8_t *dst_id;
	uint64_t dst_id_len;

	uint8_t client_rand[32];
	uint8_t server_rand[32];

	uint8_t client_private_key[32];
	uint8_t client_public_key[32];

	uint8_t server_public_key[32];

	EVP_MD_CTX *hello_ctx;
	EVP_MD_CTX *full_tls_ctx;
	uint8_t hello_hash[32];
	uint8_t full_tls_hash[32];

	// Initial Keys
	uint8_t initial_secret[32];

	uint8_t client_secret[32];
	uint8_t client_key[16];
	uint8_t client_iv[12];
	uint8_t client_hp[16];

	uint8_t server_secret[32];
	uint8_t server_key[16];
	uint8_t server_iv[12];
	uint8_t server_hp[16];

	// Handshake Keys
	uint8_t handshake_secret[32];

	uint8_t client_handshake_key[16];
	uint8_t client_handshake_iv[12];
	uint8_t client_handshake_hp[16];

	uint8_t server_handshake_key[16];
	uint8_t server_handshake_iv[12];
	uint8_t server_handshake_hp[16];

	// Application Keys
	uint8_t client_application_key[16];
	uint8_t client_application_iv[12];
	uint8_t client_application_hp[16];

	uint8_t server_application_key[16];
	uint8_t server_application_iv[12];
	uint8_t server_application_hp[16];

	QUIC_Transport_Params params;

	TLS_State tls;
	uint32_t quic_version;

	Stream_Map streams;
} Conn_Info;

void print_quic_stream(QUIC_Stream *q) {
	printf("id:       0x%llx,\n", q->id);
	printf("offset:   0x%llx,\n", q->offset);
	printf("is open:      %s,\n", BOOL_STR(q->id));
	printf("initiated by: %s,\n", BOOL_STR_CUSTOM(q->is_client_initiated, "client", "server"));
	printf("direction:    %s,\n", BOOL_STR_CUSTOM(q->is_bidirectional, "bidirectional", "unidirectional"));
	printf("crypto:      %s,\n", BOOL_STR(q->is_crypto));
}

void print_stream_entry(Stream_Entry *e) {
	printf("key: 0x%llx\n", e->key);
	printf("val:\n");
	print_quic_stream(&e->val);
}

Stream_Map stream_map_init(void) {
	Stream_Map sm = {
		.entries_cap = 8,
		.hashes_cap  = 8,
	};

	sm.entries = (Stream_Entry *)malloc(sizeof(Stream_Entry) * sm.entries_cap);
	sm.hashes  = (int64_t *)malloc(sizeof(int64_t) * sm.hashes_cap);
	for (uint64_t i = 0; i < sm.hashes_cap; i++) {
		sm.hashes[i] = -1;
	}

	return sm;
}

uint64_t fnv1a(uint64_t key) {
	uint64_t hash = 0xcbf29ce484222325;
	uint64_t fnv_prime = 0x100000001b3;

	char *key_buf = (char *)&key;
	for (int i = 0; i < sizeof(key); i++) {
		hash = hash ^ key_buf[i];
		hash = hash * fnv_prime;
	}

	return hash;
}

void stream_map_reinsert(Stream_Map *sm, Stream_Entry e, uint64_t idx) {
	uint64_t hash_val = fnv1a(e.key) & sm->hashes_cap;
	for (uint64_t i = 0; i < sm->hashes_cap; i++) {
		uint64_t cur_hash_idx = (hash_val + i) % sm->hashes_cap;
		int64_t cur_hash = sm->hashes[cur_hash_idx];

		if (cur_hash == -1) {
			sm->hashes[cur_hash_idx] = idx;
			return;
		}
	}

	return;
}

void stream_map_grow(Stream_Map *sm) {
	sm->hashes_cap = sm->hashes_cap * 2;
	sm->hashes = realloc(sm->hashes, sizeof(int64_t) * sm->hashes_cap);

	for (uint64_t i = 0; i < sm->hashes_cap; i++) {
		sm->hashes[i] = -1;
	}

	for (uint64_t i = 0; i < sm->entries_len; i++) {
		Stream_Entry entry = sm->entries[i];
		stream_map_reinsert(sm, entry, i);
	}
}

QUIC_Stream *stream_map_insert_or_get(Stream_Map *sm, uint64_t id, bool is_crypto) {
	bool is_client_initiated = id & 0x1;
	bool is_bidirectional    = (id & 0x2) >> 1;
	uint64_t raw_id = (id >> 2);
	uint64_t key = (id & ~0x3) | (uint64_t)is_crypto;

	Stream_Entry e = {
		.key = key,
		.val = (QUIC_Stream){
			.id = raw_id,
			.offset = 0,
			.is_open = true,
			.is_client_initiated = is_client_initiated,
			.is_bidirectional    = is_bidirectional,
			.is_crypto           = is_crypto
		}
	};

	int64_t next_resize_window = (3 * sm->hashes_cap) / 4;
	if (sm->entries_len >= next_resize_window) {
		stream_map_grow(sm);
	}

	uint64_t hash_val = fnv1a(key) % sm->hashes_cap;
	for (uint64_t i = 0; i < sm->hashes_cap; i++) {
		uint64_t cur_hash_idx = (hash_val + i) % sm->hashes_cap;
		int64_t cur_hash = sm->hashes[cur_hash_idx];

		if (cur_hash == -1) {
			sm->hashes[cur_hash_idx] = sm->entries_len;

			if (sm->entries_len + 1 > sm->entries_cap) {
				sm->entries_cap = sm->entries_cap * 2;
				sm->entries = (Stream_Entry *)realloc(sm->entries, sizeof(Stream_Entry) * sm->entries_cap);
			}
			sm->entries[sm->entries_len] = e;
			sm->entries_len += 1;

			return &sm->entries[sm->entries_len - 1].val;
		} else if (sm->entries[cur_hash].key == key) {
			return &sm->entries[cur_hash].val;
		}
	}

	return NULL;
}

void gen_initial_keys(Conn_Info *ci) {
	for (int i = 0; i < sizeof(ci->client_rand); i++) {
		ci->client_rand[i] = i;
	}
	for (int i = 0; i < 32; i++) {
		ci->client_private_key[i] = i + 0x20;
	}
	generate_public_key(ci->client_private_key, ci->client_public_key);

	uint8_t initial_rand[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

	char client_secret_label[] = "client in";
	char server_secret_label[] = "server in";
	char key_label[]           = "quic key";
	char iv_label[]            = "quic iv";
	char hp_label[]            = "quic hp";

	hdkf_extract(ci->initial_secret, initial_salt, sizeof(initial_salt), initial_rand, sizeof(initial_rand));

	hdkf_expand_label(ci->client_secret, sizeof(ci->client_secret), ci->initial_secret, client_secret_label);
	hdkf_expand_label(ci->client_key,    sizeof(ci->client_key),    ci->client_secret,  key_label);
	hdkf_expand_label(ci->client_iv,     sizeof(ci->client_iv),     ci->client_secret,  iv_label);
	hdkf_expand_label(ci->client_hp,     sizeof(ci->client_hp),     ci->client_secret,  hp_label);


	hdkf_expand_label(ci->server_secret, sizeof(ci->server_secret), ci->initial_secret, server_secret_label);
	hdkf_expand_label(ci->server_key,    sizeof(ci->server_key),    ci->server_secret,  key_label);
	hdkf_expand_label(ci->server_iv,     sizeof(ci->server_iv),     ci->server_secret,  iv_label);
	hdkf_expand_label(ci->server_hp,     sizeof(ci->server_hp),     ci->server_secret,  hp_label);

	if (DEBUG_DUMP) {
		printf("INITIAL KEYS\n");
		printf("initial secret:"); dump_flat_bytes(ci->initial_secret, sizeof(ci->initial_secret)); printf("\n");

		printf("client secret: "); dump_flat_bytes(ci->client_secret, sizeof(ci->client_secret)); printf("\n");
		printf("client key:    "); dump_flat_bytes(ci->client_key,    sizeof(ci->client_key));    printf("\n");
		printf("client iv:     "); dump_flat_bytes(ci->client_iv,     sizeof(ci->client_iv));     printf("\n");
		printf("client hp:     "); dump_flat_bytes(ci->client_hp,     sizeof(ci->client_hp));     printf("\n");

		printf("server secret: "); dump_flat_bytes(ci->server_secret, sizeof(ci->server_secret)); printf("\n");
		printf("server key:    "); dump_flat_bytes(ci->server_key,    sizeof(ci->server_key));    printf("\n");
		printf("server iv:     "); dump_flat_bytes(ci->server_iv,     sizeof(ci->server_iv));     printf("\n");
		printf("server hp:     "); dump_flat_bytes(ci->server_hp,     sizeof(ci->server_hp));     printf("\n");
	}

	ci->hello_ctx    = init_sha256();
	ci->full_tls_ctx = init_sha256();
}

bool gen_handshake_keys(Conn_Info *ci) {
	finish_sha256_sum(ci->hello_ctx, ci->hello_hash);

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
	hdkf_extract(ci->handshake_secret, derived_secret, sizeof(derived_secret), shared_secret, sizeof(shared_secret));

	hdkf_expand_label_with_extra(client_secret, sizeof(client_secret), ci->handshake_secret, ci->hello_hash, sizeof(ci->hello_hash), client_secret_label);

	hdkf_expand_label(ci->client_handshake_key, sizeof(ci->client_handshake_key), client_secret, key_label);
	hdkf_expand_label(ci->client_handshake_iv,  sizeof(ci->client_handshake_iv),  client_secret, iv_label);
	hdkf_expand_label(ci->client_handshake_hp,  sizeof(ci->client_handshake_hp),  client_secret, hp_label);

	hdkf_expand_label_with_extra(server_secret, sizeof(server_secret), ci->handshake_secret, ci->hello_hash, sizeof(ci->hello_hash), server_secret_label);

	hdkf_expand_label(ci->server_handshake_key, sizeof(ci->server_handshake_key), server_secret, key_label);
	hdkf_expand_label(ci->server_handshake_iv,  sizeof(ci->server_handshake_iv),  server_secret, iv_label);
	hdkf_expand_label(ci->server_handshake_hp,  sizeof(ci->server_handshake_hp),  server_secret, hp_label);

	if (DEBUG_DUMP) {
		printf("HANDSHAKE KEYS\n");
		printf("hello hash:    "); dump_flat_bytes(ci->hello_hash,       sizeof(ci->hello_hash)); printf("\n");
		printf("initial secret:"); dump_flat_bytes(ci->handshake_secret, sizeof(ci->handshake_secret)); printf("\n");

		printf("client secret: "); dump_flat_bytes(client_secret,               sizeof(client_secret)); printf("\n");
		printf("client key:    "); dump_flat_bytes(ci->client_handshake_key,    sizeof(ci->client_handshake_key)); printf("\n");
		printf("client iv:     "); dump_flat_bytes(ci->client_handshake_iv,     sizeof(ci->client_handshake_iv));  printf("\n");
		printf("client hp:     "); dump_flat_bytes(ci->client_handshake_hp,     sizeof(ci->client_handshake_hp));  printf("\n");

		printf("server secret: "); dump_flat_bytes(server_secret,               sizeof(server_secret)); printf("\n");
		printf("server key:    "); dump_flat_bytes(ci->server_handshake_key,    sizeof(ci->server_handshake_key)); printf("\n");
		printf("server iv:     "); dump_flat_bytes(ci->server_handshake_iv,     sizeof(ci->server_handshake_iv));  printf("\n");
		printf("server hp:     "); dump_flat_bytes(ci->server_handshake_hp,     sizeof(ci->server_handshake_hp));  printf("\n");
	}
	
	return true;
}

bool gen_application_keys(Conn_Info *ci) {
	finish_sha256_sum(ci->full_tls_ctx, ci->full_tls_hash);

	uint8_t zero_key[32] = {};
	uint8_t blank_salt[1] = {};

	uint8_t derived_secret[32];
	uint8_t master_secret[32];

	uint8_t client_secret[32];
	uint8_t server_secret[32];

	char derived_label[]       = "derived";
	char client_secret_label[] = "c ap traffic";
	char server_secret_label[] = "s ap traffic";
	char key_label[]           = "quic key";
	char iv_label[]            = "quic iv";
	char hp_label[]            = "quic hp";

	hdkf_expand_label_with_extra(derived_secret, sizeof(derived_secret), ci->handshake_secret, empty_sha256_hash, sizeof(empty_sha256_hash), derived_label);
	hdkf_extract(master_secret, derived_secret, sizeof(derived_secret), zero_key, sizeof(zero_key));

	hdkf_expand_label_with_extra(client_secret, sizeof(client_secret), master_secret, ci->full_tls_hash, sizeof(ci->full_tls_hash), client_secret_label);

	hdkf_expand_label(ci->client_application_key, sizeof(ci->client_application_key), client_secret, key_label);
	hdkf_expand_label(ci->client_application_iv,  sizeof(ci->client_application_iv),  client_secret, iv_label);
	hdkf_expand_label(ci->client_application_hp,  sizeof(ci->client_application_hp),  client_secret, hp_label);

	hdkf_expand_label_with_extra(server_secret, sizeof(server_secret), master_secret, ci->full_tls_hash, sizeof(ci->full_tls_hash), server_secret_label);

	hdkf_expand_label(ci->server_application_key, sizeof(ci->server_application_key), server_secret, key_label);
	hdkf_expand_label(ci->server_application_iv,  sizeof(ci->server_application_iv),  server_secret, iv_label);
	hdkf_expand_label(ci->server_application_hp,  sizeof(ci->server_application_hp),  server_secret, hp_label);

	if (DEBUG_DUMP) {
		printf("APPLICATION KEYS\n");
		printf("full hash:     "); dump_flat_bytes(ci->full_tls_hash,             sizeof(ci->full_tls_hash));          printf("\n");
		printf("client secret: "); dump_flat_bytes(client_secret,                 sizeof(client_secret));              printf("\n");
		printf("client key:    "); dump_flat_bytes(ci->client_application_key,    sizeof(ci->client_application_key)); printf("\n");
		printf("client iv:     "); dump_flat_bytes(ci->client_application_iv,     sizeof(ci->client_application_iv));  printf("\n");
		printf("client hp:     "); dump_flat_bytes(ci->client_application_hp,     sizeof(ci->client_application_hp));  printf("\n");

		printf("server secret: "); dump_flat_bytes(server_secret,                 sizeof(server_secret));              printf("\n");
		printf("server key:    "); dump_flat_bytes(ci->server_application_key,    sizeof(ci->server_application_key)); printf("\n");
		printf("server iv:     "); dump_flat_bytes(ci->server_application_iv,     sizeof(ci->server_application_iv));  printf("\n");
		printf("server hp:     "); dump_flat_bytes(ci->server_application_hp,     sizeof(ci->server_application_hp));  printf("\n");
	}
	
	return true;
}

int build_initial_packet(Conn_Info *ci, uint8_t *buffer, size_t buffer_size) {
	if (buffer_size < 1200) { return 0; }

	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	// Build TLS Client Hello
	uint8_t client_hello[1500] = {};
	int64_t client_hello_size = build_client_hello(
		client_hello, sizeof(client_hello),
		ci->hostname, strlen(ci->hostname),
		ci->protocol, strlen(ci->protocol),
		ci->client_rand, sizeof(ci->client_rand),
		ci->client_public_key, sizeof(ci->client_public_key),
		ci->src_id, ci->src_id_len,
		&ci->params
	);
	update_sha256_sum(ci->hello_ctx,    client_hello, client_hello_size);
	update_sha256_sum(ci->full_tls_ctx, client_hello, client_hello_size);

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
	bool is_long   = (pkt_hdr_byte & 0x80) >> 7;
	bool fixed_bit = (pkt_hdr_byte & 0x40) >> 6;

	uint8_t hdr_mask_bits = 0;
	uint8_t payload_mask[16] = {};
	uint64_t pkt_len = 0;

	uint8_t *server_hp  = NULL;
	uint8_t *server_key = NULL;
	uint8_t *server_iv  = NULL;

	TLS_Conn_State pkt_state;

	if (is_long) {
		hdr_mask_bits = 0x0F;

		uint8_t pkt_type  = (pkt_hdr_byte & 0x30) >> 4;
		printf("pkt %x | long-header, fixed: %u, type: (%u) %s\n", pkt_hdr_byte, fixed_bit, pkt_type, quic_packet_longtype_to_str(pkt_type));

		uint32_t quic_version = read_u32_be(&s);
		if (quic_version != 0x1) {
			printf("unsupported version of QUIC! (0x%x)\n", quic_version);
			return 0;
		}

		uint8_t dst_id_len = read_u8(&s);
		uint8_t *dst_id = read_data(&s, dst_id_len);

		ci->dst_id_len = dst_id_len;
		memcpy(ci->dst_id, dst_id, dst_id_len);

		uint8_t src_id_len = read_u8(&s);
		uint8_t *src_id = read_data(&s, src_id_len);

		switch ((QUIC_Packet_LongType)pkt_type) {
			case LongType_Initial: {
				// Skip token
				uint8_t token = read_u8(&s);

				pkt_len = read_varint(&s);
				pkt_state = TLS_State_Initial;
			} break;
			case LongType_Handshake: {
				pkt_len = read_varint(&s);
				pkt_state = TLS_State_Handshake;
			} break;
			default: {
				printf("unhandled packet type (hdr: %x) %s\n", pkt_hdr_byte, quic_packet_longtype_to_str(pkt_type));
				return 0;
			}
		}
	} else {
		hdr_mask_bits = 0x1F;

		bool spin_bit  = (pkt_hdr_byte & 0x20) >> 5;
		printf("pkt %x | short-header, fixed: %u, spin bit: %u\n", pkt_hdr_byte, fixed_bit, spin_bit);

		uint8_t *dst_id = read_data(&s, ci->dst_id_len);
		printf("dst id:"); dump_bytes(dst_id, ci->dst_id_len);

		pkt_len = s.cap - s.len;
		pkt_state = TLS_State_Application;
	}

	switch (pkt_state) {
		case TLS_State_Application: {
			server_hp  = ci->server_application_hp;
			server_key = ci->server_application_key;
			server_iv  = ci->server_application_iv;
		} break;
		case TLS_State_Handshake: {
			server_hp  = ci->server_handshake_hp;
			server_key = ci->server_handshake_key;
			server_iv  = ci->server_handshake_iv;
		} break;
		case TLS_State_Initial: {
			server_hp  = ci->server_hp;
			server_key = ci->server_key;
			server_iv  = ci->server_iv;
		} break;
	}
	printf("trying decode for TLS state %s\n", tls_conn_state_to_str(pkt_state));

	uint8_t *sample = s.data + s.len + 4;
	generate_mask(payload_mask, sample, server_hp);

	// unprotect packet header
	s.data[0] = s.data[0] ^ (payload_mask[0] & hdr_mask_bits);
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

	printf("packet is %llu bytes, pkt num: %llu | len: %llu, hdr len: %llu\n", pkt_len, pkt_num, pkt_num_len, pkt_hdr_size);

	if (!decrypt_buffer(plaintext_buffer, encrypted_buffer, encrypted_size, server_key, server_iv, pkt_num, aead, pkt_hdr, pkt_hdr_size)) {
		printf("failed to decrypt server packet!\n");
		printf("protected bytes: "); dump_bytes(encrypted_buffer, encrypted_size);
		printf("aead: "); dump_bytes(aead, aead_len);
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
			case Frame_NewConnectionID: {
				uint64_t seq_num = read_varint(&pt);
				uint64_t retire_prior_to = read_varint(&pt);
				uint8_t new_conn_len = read_u8(&pt);
				uint8_t *new_conn_id = read_data(&pt, new_conn_len);
				uint8_t *stateless_reset_token = read_data(&pt, 16);
				printf("STATELESS RESET TOKEN: "); dump_flat_bytes(stateless_reset_token, 16); printf("\n");

				ci->src_id_len = new_conn_len;
				memcpy(&ci->src_id, new_conn_id, ci->src_id_len);

				printf("new connection id: seq num: 0x%08llx, retire prior to: 0x%08llx, new dst id: ", seq_num, retire_prior_to); dump_flat_bytes(new_conn_id, new_conn_len); printf(", stateless reset token:"); dump_flat_bytes(stateless_reset_token, 16); printf("\n");
			} break;
			case Frame_Ack1: {
				uint8_t largest_ack = read_u8(&pt);
				uint64_t ack_delay = read_varint(&pt);
				uint8_t ack_range_count = read_u8(&pt);
				uint64_t first_ack_range = read_varint(&pt);
			} break;
			case Frame_Stream1: case Frame_Stream2: case Frame_Stream3: case Frame_Stream4:
			case Frame_Stream5: case Frame_Stream6: case Frame_Stream7: case Frame_Stream8: {
				bool has_offset = (frame_type_byte & 0x04) >> 2;
				bool has_len    = (frame_type_byte & 0x02) >> 1;
				bool is_final   = (frame_type_byte & 0x01);
				uint64_t stream_id = read_varint(&pt);

				uint64_t offset = 0;
				uint64_t size = 0;
				if (has_offset) {
					offset = read_varint(&pt);
				}
				if (has_len) {
					size = read_varint(&pt);
				} else {
					size = pt.cap - pt.len;
				}

				uint8_t *stream_data = read_data(&pt, size);
				printf("off: 0x%08llx, len: 0x%08llx, final: %u\n", offset, size, is_final);
				printf("stream bytes: "); dump_bytes(stream_data, size);

				QUIC_Stream *stream = stream_map_insert_or_get(&ci->streams, stream_id, false);

				// If no forward progress is getting made, this is a repeat packet
				if (offset < stream->offset) {
					printf("repeat stream packet?\n");
					return Message_Failed;
				}
				stream->offset += size;

			} break;
			case Frame_Crypto: {
				uint64_t offset = read_varint(&pt);
				uint64_t size   = read_varint(&pt);
				uint8_t *data = read_data(&pt, size);
				printf("crypto frame off: %llu, size: %llu\n", offset, size);

				QUIC_Stream *stream = stream_map_insert_or_get(&ci->streams, 0, true);

				// If no forward progress is getting made, this is a repeat packet
				if (offset < stream->offset) {
					printf("repeat crypto packet?\n");
					return Message_Failed;
				}
				stream->offset += size;

				switch (ci->tls.state) {
					case TLS_State_Initial: {
						Message_State state = tls_initial(&ci->tls, data, size, ci->hello_ctx, ci->full_tls_ctx, ci->server_public_key, sizeof(ci->server_public_key), ci->server_rand);
						if (state != Message_Success) { return state; }

						gen_handshake_keys(ci);
						ci->tls.state = TLS_State_Handshake;
						stream->offset = 0;
					} break;
					case TLS_State_Handshake: {
						Message_State state = tls_handshake(&ci->tls, ci->full_tls_ctx, data, size, &ci->params);
						if (state != Message_Success) { return state; }

						gen_application_keys(ci);
						ci->tls.state = TLS_State_Application;
						stream->offset = 0;
					} break;
					default: {
						printf("unhandled TLS state! %d\n", ci->tls.state);
						return Message_Failed;
					}
				}
			} break;
			case Frame_Padding: {
				// Do nothing
			} break;
			case Frame_HandshakeDone: {
				// Do nothing
			} break;
			default: {
				printf("Unhandled frame type: (0x%x) %s\n", frame_type, quic_frame_type_to_str(frame_type));
				return Message_Failed;
			}
		}
	}

	return Message_Success;
}

bool test_handshake(void) {
	uint8_t response_1[] = {
		0xcd, 0x00, 0x00, 0x00, 0x01, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x05,
		0x73, 0x5f, 0x63, 0x69, 0x64, 0x00, 0x40, 0x75, 0x3a, 0x83, 0x68, 0x55,
		0xd5, 0xd9, 0xc8, 0x23, 0xd0, 0x7c, 0x61, 0x68, 0x82, 0xca, 0x77, 0x02,
		0x79, 0x24, 0x98, 0x64, 0xb5, 0x56, 0xe5, 0x16, 0x32, 0x25, 0x7e, 0x2d,
		0x8a, 0xb1, 0xfd, 0x0d, 0xc0, 0x4b, 0x18, 0xb9, 0x20, 0x3f, 0xb9, 0x19,
		0xd8, 0xef, 0x5a, 0x33, 0xf3, 0x78, 0xa6, 0x27, 0xdb, 0x67, 0x4d, 0x3c,
		0x7f, 0xce, 0x6c, 0xa5, 0xbb, 0x3e, 0x8c, 0xf9, 0x01, 0x09, 0xcb, 0xb9,
		0x55, 0x66, 0x5f, 0xc1, 0xa4, 0xb9, 0x3d, 0x05, 0xf6, 0xeb, 0x83, 0x25,
		0x2f, 0x66, 0x31, 0xbc, 0xad, 0xc7, 0x40, 0x2c, 0x10, 0xf6, 0x5c, 0x52,
		0xed, 0x15, 0xb4, 0x42, 0x9c, 0x9f, 0x64, 0xd8, 0x4d, 0x64, 0xfa, 0x40,
		0x6c, 0xf0, 0xb5, 0x17, 0xa9, 0x26, 0xd6, 0x2a, 0x54, 0xa9, 0x29, 0x41,
		0x36, 0xb1, 0x43, 0xb0, 0x33
	};

	uint8_t response_2[] = {
		0xed, 0x00, 0x00, 0x00, 0x01, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x05,
		0x73, 0x5f, 0x63, 0x69, 0x64, 0x44, 0x14, 0xb7, 0xdd, 0x73, 0xae, 0x29,
		0x62, 0x09, 0xdf, 0xf2, 0xd0, 0x2d, 0x3d, 0x50, 0xaf, 0x69, 0x21, 0x76,
		0xdd, 0x4d, 0x50, 0x9f, 0xe8, 0xcb, 0x1b, 0x46, 0xe4, 0x5b, 0x09, 0x36,
		0x4d, 0x81, 0x5f, 0xa7, 0xa5, 0x74, 0x8e, 0x21, 0x80, 0xda, 0xd2, 0xb7,
		0xb6, 0x68, 0xca, 0xb8, 0x6f, 0xbd, 0xc2, 0x98, 0x8c, 0x45, 0xcb, 0xb8,
		0x51, 0xdd, 0xcf, 0x16, 0x01, 0xb7, 0x80, 0xd7, 0x48, 0xb9, 0xee, 0x64,
		0x1e, 0xbc, 0xbe, 0x20, 0x12, 0x6e, 0x32, 0x26, 0x7e, 0x66, 0x4d, 0x2f,
		0x37, 0xcf, 0x53, 0xb7, 0x53, 0xd1, 0x24, 0x71, 0x7c, 0x2e, 0x13, 0xc4,
		0x8a, 0x09, 0xe3, 0x42, 0x8b, 0x11, 0xdc, 0x73, 0xba, 0xeb, 0xd4, 0x98,
		0xe8, 0xca, 0xf5, 0xbe, 0xce, 0xfe, 0xa7, 0x60, 0xd0, 0xe7, 0xa5, 0xcd,
		0xb7, 0x6b, 0x52, 0xbc, 0xb1, 0x92, 0x29, 0x97, 0x3e, 0x5d, 0x09, 0xaa,
		0x05, 0x5e, 0x9c, 0x97, 0x18, 0xdc, 0x58, 0x14, 0x54, 0x77, 0x5c, 0x58,
		0xec, 0xdd, 0x5e, 0xe7, 0xe7, 0x72, 0x78, 0xf5, 0x60, 0x10, 0x70, 0x40,
		0x41, 0x62, 0xa7, 0x9e, 0xe8, 0xc5, 0x96, 0x45, 0xd6, 0xca, 0x24, 0xa2,
		0x00, 0x18, 0x6a, 0xe9, 0x9c, 0xe4, 0x7e, 0xac, 0xe1, 0xcf, 0xc9, 0x52,
		0x7b, 0x24, 0xae, 0x8b, 0xc6, 0xcc, 0xdb, 0xac, 0xb7, 0x9b, 0x81, 0xc9,
		0x1a, 0x26, 0x95, 0x47, 0x07, 0xba, 0x35, 0xcb, 0xa0, 0xca, 0xe9, 0xaf,
		0xf4, 0x18, 0xc6, 0xe0, 0x8d, 0xa6, 0x50, 0x61, 0x63, 0xa3, 0x9f, 0x19,
		0xb6, 0x76, 0xa6, 0x6a, 0xc1, 0x74, 0xe3, 0x29, 0x5f, 0x1a, 0xb9, 0xea,
		0x73, 0x83, 0xa9, 0xc2, 0x85, 0xd7, 0x3e, 0x95, 0x75, 0x8d, 0xc9, 0xbd,
		0x8d, 0xa9, 0x07, 0x34, 0xa9, 0xfe, 0xdf, 0xd7, 0xe1, 0xf7, 0x4d, 0x2b,
		0x69, 0xc7, 0x0b, 0xf7, 0x39, 0xa4, 0x8c, 0x5a, 0x5d, 0x0a, 0xfa, 0x0b,
		0xfa, 0x16, 0x03, 0x47, 0x1b, 0x0c, 0x61, 0xa9, 0xca, 0xde, 0x12, 0x0b,
		0x39, 0x86, 0xa6, 0xce, 0x02, 0x95, 0xbe, 0x82, 0x28, 0xc6, 0x92, 0x70,
		0x13, 0xb0, 0x6d, 0xa5, 0x8d, 0x31, 0x99, 0x62, 0x31, 0xb9, 0xe3, 0x15,
		0x0b, 0xb5, 0x82, 0x70, 0x96, 0x0e, 0x61, 0xcb, 0xc6, 0x69, 0x8a, 0x2f,
		0x13, 0x79, 0xa2, 0x25, 0x84, 0x65, 0xda, 0x73, 0x25, 0xb3, 0x49, 0xc6,
		0xcd, 0x55, 0xd1, 0x05, 0xfd, 0x54, 0x85, 0xfd, 0x0a, 0xc7, 0x9a, 0x1d,
		0xf1, 0xdb, 0xba, 0x7f, 0x85, 0xb4, 0x9b, 0x72, 0x36, 0x5b, 0xfa, 0xb9,
		0xd5, 0x78, 0xe0, 0x1d, 0xcb, 0xff, 0x85, 0x15, 0xa6, 0x32, 0xfd, 0x70,
		0x01, 0x38, 0x2e, 0xd9, 0x0f, 0x6c, 0xdc, 0xb1, 0x7d, 0xb9, 0x9a, 0x33,
		0xfa, 0x11, 0x81, 0xf6, 0xf6, 0x1a, 0x89, 0xe7, 0x83, 0xcf, 0xb0, 0x42,
		0xfc, 0x0f, 0x2f, 0x67, 0xcd, 0xb6, 0x0e, 0x89, 0xf2, 0x63, 0x88, 0x56,
		0x81, 0xae, 0x64, 0x5a, 0x1c, 0x7a, 0xb1, 0x59, 0x0e, 0xb2, 0xf8, 0x46,
		0x9f, 0x46, 0x0f, 0x04, 0xe0, 0x9f, 0xea, 0x2a, 0x3a, 0x41, 0x1b, 0x49,
		0x86, 0x63, 0x01, 0x0b, 0x3c, 0x38, 0x2a, 0x3f, 0x25, 0x83, 0x7c, 0x2c,
		0x70, 0x86, 0xaf, 0x5a, 0x9a, 0xd2, 0x90, 0xcf, 0x3c, 0xcf, 0x1a, 0xc6,
		0xeb, 0x0f, 0x44, 0x55, 0x35, 0xe8, 0xb0, 0x0a, 0x55, 0x7c, 0x87, 0xa5,
		0x3d, 0x93, 0x07, 0x14, 0x62, 0xa0, 0xbc, 0x22, 0x61, 0x4e, 0x5c, 0x3a,
		0xe0, 0x84, 0x17, 0xb7, 0x20, 0xa7, 0x36, 0xc1, 0xad, 0x48, 0xea, 0x37,
		0x75, 0xcd, 0x0f, 0x00, 0x9f, 0x0c, 0x57, 0x50, 0x0e, 0x0b, 0xb2, 0xe7,
		0xe9, 0xc5, 0x3f, 0x83, 0x69, 0x9a, 0x47, 0xe5, 0xf1, 0x3b, 0xb2, 0x07,
		0x72, 0xab, 0x23, 0x50, 0x64, 0x24, 0xb7, 0x6f, 0x6e, 0xf9, 0x6a, 0x61,
		0xc9, 0x17, 0x22, 0x6e, 0x6e, 0x04, 0x8d, 0xe6, 0xf8, 0x24, 0x26, 0xca,
		0x63, 0xea, 0xbf, 0x3b, 0x59, 0x43, 0xaf, 0x0b, 0x5f, 0x0d, 0x12, 0x3d,
		0x9a, 0xf0, 0x45, 0xbb, 0x35, 0x7c, 0xad, 0xbd, 0x10, 0x92, 0xad, 0x0a,
		0x1d, 0x75, 0x51, 0x16, 0x2a, 0x3b, 0x4b, 0x48, 0x6c, 0x27, 0x1e, 0x00,
		0x24, 0x4b, 0x23, 0xd8, 0xad, 0xec, 0x81, 0xc9, 0x2e, 0x31, 0x23, 0x9c,
		0x75, 0xaf, 0x41, 0xcb, 0x07, 0x98, 0x08, 0x57, 0x1b, 0x48, 0xac, 0xb5,
		0x07, 0x33, 0x3f, 0xfb, 0xf1, 0xa4, 0x86, 0xd8, 0x05, 0x3e, 0xdc, 0xc8,
		0x62, 0xb6, 0xa9, 0xbf, 0xd3, 0x6a, 0x09, 0xcd, 0xdb, 0xa3, 0x29, 0x1b,
		0x9b, 0x8b, 0xa1, 0x58, 0x49, 0x34, 0x59, 0x80, 0x5c, 0xe2, 0x41, 0xda,
		0xf5, 0xc1, 0x30, 0x85, 0x99, 0xfc, 0x0e, 0x6e, 0x6e, 0xa7, 0x10, 0x30,
		0x33, 0xb2, 0x94, 0xcc, 0x7a, 0x5f, 0xdb, 0x2d, 0x46, 0x54, 0xf1, 0xd4,
		0x40, 0x78, 0x25, 0xeb, 0xc3, 0x75, 0xab, 0xdf, 0xb2, 0xcc, 0xa1, 0xab,
		0xf5, 0xa2, 0x41, 0x34, 0x3d, 0xec, 0x3b, 0x16, 0x5d, 0x32, 0x0a, 0xf8,
		0x4b, 0xc1, 0xfa, 0x21, 0x11, 0x2e, 0xfd, 0xb9, 0xd4, 0x5c, 0x6c, 0xfc,
		0x7b, 0x8a, 0x64, 0x42, 0xff, 0x59, 0x3d, 0x09, 0x21, 0x93, 0x36, 0xfa,
		0x07, 0x56, 0xd9, 0xe4, 0x5b, 0xab, 0x4f, 0xa6, 0x33, 0x94, 0xa2, 0xa8,
		0x80, 0x3d, 0xf4, 0x67, 0x8e, 0x79, 0x21, 0x6f, 0xdf, 0x13, 0x1f, 0x55,
		0x82, 0x2f, 0x9e, 0xad, 0x69, 0x4a, 0xb7, 0x5e, 0xe2, 0x54, 0x96, 0xe6,
		0xb7, 0x8c, 0x3b, 0x09, 0x04, 0x66, 0x58, 0xe2, 0xc4, 0x27, 0xdd, 0xc4,
		0x53, 0x8a, 0xf8, 0xde, 0x2a, 0xcb, 0x81, 0x39, 0x8b, 0x74, 0x82, 0x83,
		0x37, 0xf2, 0x69, 0xcb, 0x03, 0x1d, 0x99, 0x7a, 0x5c, 0xf6, 0x3e, 0x11,
		0xab, 0x05, 0x0a, 0xa8, 0xae, 0xe1, 0xf0, 0x79, 0x62, 0xdd, 0xd7, 0x51,
		0x5a, 0xb6, 0x0e, 0x19, 0x2e, 0x40, 0x3c, 0x30, 0x03, 0x11, 0xe9, 0xe4,
		0xb9, 0xb7, 0x0f, 0x16, 0x15, 0x02, 0x9d, 0x07, 0xfe, 0x1c, 0x23, 0x19,
		0x39, 0x02, 0x71, 0x49, 0xf4, 0xfd, 0x29, 0x72, 0x02, 0x3a, 0x55, 0xde,
		0x29, 0x35, 0x65, 0x05, 0xfb, 0xe7, 0x49, 0x90, 0x8c, 0x62, 0xaa, 0x33,
		0xeb, 0x25, 0x9a, 0x39, 0x9b, 0xf7, 0x11, 0xb9, 0x2b, 0x61, 0x6c, 0xb7,
		0x48, 0xde, 0x73, 0xc8, 0xbf, 0xad, 0xd5, 0xd4, 0x3e, 0x2d, 0xae, 0x91,
		0x6a, 0x7b, 0xa0, 0xdb, 0x61, 0xdf, 0xcd, 0x6f, 0xaf, 0x95, 0x76, 0x08,
		0x26, 0x2b, 0x68, 0x34, 0xe3, 0x31, 0x85, 0xb8, 0xd5, 0x59, 0x8f, 0x87,
		0xe6, 0x99, 0x2a, 0xac, 0xf5, 0x76, 0x96, 0xad, 0xd5, 0x55, 0x8a, 0x7d,
		0x96, 0x94, 0x38, 0x1f, 0x5d, 0x7d, 0x65, 0x9d, 0xa2, 0xde, 0x95, 0x1b,
		0x60, 0x74, 0x78, 0xf6, 0x1d, 0xa2, 0x08, 0xa2, 0x4a, 0x07, 0xba, 0x8d,
		0xa0, 0x02, 0x58, 0xfa, 0x7f, 0x2f, 0xe1, 0x0d, 0xef, 0x61, 0x83, 0x26,
		0x7f, 0x5d, 0x38, 0xe0, 0x4c, 0x94, 0x23, 0x00, 0xb9, 0xc8, 0x74, 0xe8,
		0x98, 0x3c, 0x1b, 0xe1, 0x4e, 0x16, 0x08, 0xff, 0xdc, 0xa6, 0x7d, 0x7e,
		0x45, 0x13, 0xcc, 0x0c, 0xb9, 0xca, 0xb8, 0x1d, 0x63, 0x19, 0xdd, 0x10,
		0x74, 0xb2, 0x17, 0xe5, 0x19, 0x54, 0x65, 0x13, 0x1e, 0x06, 0xdd, 0x0b,
		0xaf, 0xab, 0xa8, 0x4e, 0xb5, 0x2c, 0x22, 0xa4, 0xa8, 0xc6, 0x12, 0xa4,
		0x05, 0xfe, 0x6c, 0x87, 0x42, 0x32, 0xe4, 0xa9, 0x34, 0x61, 0x1b, 0xc7,
		0x3c, 0x56, 0xfe, 0x70, 0xb2, 0xcb, 0x7a, 0x59, 0x6c, 0x1f, 0x53, 0xc7,
		0x29, 0xb6, 0x64, 0x3c, 0xbd, 0x70, 0xd5, 0x30, 0xfe, 0x31, 0x96, 0x06,
		0x9f, 0xc0, 0x07, 0x8e, 0x89, 0xfb, 0xb7, 0x0d, 0xc1, 0xb3, 0x8a, 0xb4,
		0xe1, 0x77, 0x0c, 0x8f, 0xfb, 0x53, 0x31, 0x6d, 0x67, 0x3a, 0x32, 0xb8,
		0x92, 0x59, 0xb5, 0xd3, 0x3e, 0x94, 0xad
	};

	uint8_t response_3[] = {
		0xe5, 0x00, 0x00, 0x00, 0x01, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x05,
		0x73, 0x5f, 0x63, 0x69, 0x64, 0x40, 0xcf, 0x4f, 0x44, 0x20, 0xf9, 0x19,
		0x68, 0x1c, 0x3f, 0x0f, 0x10, 0x2a, 0x30, 0xf5, 0xe6, 0x47, 0xa3, 0x39,
		0x9a, 0xbf, 0x54, 0xbc, 0x8e, 0x80, 0x45, 0x31, 0x34, 0x99, 0x6b, 0xa3,
		0x30, 0x99, 0x05, 0x62, 0x42, 0xf3, 0xb8, 0xe6, 0x62, 0xbb, 0xfc, 0xe4,
		0x2f, 0x3e, 0xf2, 0xb6, 0xba, 0x87, 0x15, 0x91, 0x47, 0x48, 0x9f, 0x84,
		0x79, 0xe8, 0x49, 0x28, 0x4e, 0x98, 0x3f, 0xd9, 0x05, 0x32, 0x0a, 0x62,
		0xfc, 0x7d, 0x67, 0xe9, 0x58, 0x77, 0x97, 0x09, 0x6c, 0xa6, 0x01, 0x01,
		0xd0, 0xb2, 0x68, 0x5d, 0x87, 0x47, 0x81, 0x11, 0x78, 0x13, 0x3a, 0xd9,
		0x17, 0x2b, 0x7f, 0xf8, 0xea, 0x83, 0xfd, 0x81, 0xa8, 0x14, 0xba, 0xe2,
		0x7b, 0x95, 0x3a, 0x97, 0xd5, 0x7e, 0xbf, 0xf4, 0xb4, 0x71, 0x0d, 0xba,
		0x8d, 0xf8, 0x2a, 0x6b, 0x49, 0xd7, 0xd7, 0xfa, 0x3d, 0x81, 0x79, 0xcb,
		0xdb, 0x86, 0x83, 0xd4, 0xbf, 0xa8, 0x32, 0x64, 0x54, 0x01, 0xe5, 0xa5,
		0x6a, 0x76, 0x53, 0x5f, 0x71, 0xc6, 0xfb, 0x3e, 0x61, 0x6c, 0x24, 0x1b,
		0xb1, 0xf4, 0x3b, 0xc1, 0x47, 0xc2, 0x96, 0xf5, 0x91, 0x40, 0x29, 0x97,
		0xed, 0x49, 0xaa, 0x0c, 0x55, 0xe3, 0x17, 0x21, 0xd0, 0x3e, 0x14, 0x11,
		0x4a, 0xf2, 0xdc, 0x45, 0x8a, 0xe0, 0x39, 0x44, 0xde, 0x51, 0x26, 0xfe,
		0x08, 0xd6, 0x6a, 0x6e, 0xf3, 0xba, 0x2e, 0xd1, 0x02, 0x5f, 0x98, 0xfe,
		0xa6, 0xd6, 0x02, 0x49, 0x98, 0x18, 0x46, 0x87, 0xdc, 0x06
	};

	uint8_t response_4[] = {
		0xe5, 0x00, 0x00, 0x00, 0x01, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x05,
		0x73, 0x5f, 0x63, 0x69, 0x64, 0x40, 0x16, 0xa4, 0x87, 0x5b, 0x25, 0x16,
		0x9e, 0x6f, 0x1b, 0x81, 0x7e, 0x46, 0x23, 0xe1, 0xac, 0xbe, 0x1d, 0xb3,
		0x89, 0x9b, 0x00, 0xec, 0xfb
	};

	uint8_t response_5[] = {
		0x49, 0x63, 0x5f, 0x63, 0x69, 0x64, 0xcd, 0x9a, 0x64, 0x12, 0x40, 0x57,
		0xc8, 0x83, 0xe9, 0x4d, 0x9c, 0x29, 0x6b, 0xaa, 0x8c, 0xa0, 0xea, 0x6e,
		0x3a, 0x21, 0xfa, 0xaf, 0x99, 0xaf, 0x2f, 0xe1, 0x03, 0x21, 0x69, 0x20,
		0x57, 0xd2
	};

	uint8_t response_6[] = {
		0x54, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x95, 0x18, 0xc4, 0xa5, 0xff, 0xeb,
		0x17, 0xb6, 0x7e, 0xc2, 0x7f, 0x97, 0xe5, 0x0d, 0x27, 0x1d, 0xc7, 0x02,
		0xd9, 0x2c, 0xef, 0xb0, 0x68, 0x8b, 0xe9, 0xfd, 0x7b, 0x30, 0x2d, 0x9e,
		0xb4, 0x7c, 0xdf, 0x1f, 0xc4, 0xcd, 0x9a, 0xac
	};

	uint8_t dst_id[8] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
	int dst_id_len = sizeof(dst_id);

	uint8_t src_id[] = "c_cid";
	int src_id_len = sizeof(src_id) - 1;

	Conn_Info ci = {
		.streams    = stream_map_init(),
		.hostname   = "example.ulfheim.net",
		.protocol   = "ping/1.0",
		.dst_id     = dst_id,
		.dst_id_len = dst_id_len,
		.src_id     = src_id,
		.src_id_len = src_id_len,
	};
	gen_initial_keys(&ci);

	uint8_t send_buffer[1500] = {};
	int pkt_size = build_initial_packet(&ci, send_buffer, sizeof(send_buffer));

	int i = 0;
	Message_State state = Message_Failed;
	for (int i = 0; i < 6; i++) {
		ssize_t recv_bytes = 0;
		uint8_t recv_buffer[1500];
		switch (i) {
			case 0: {
				recv_bytes = sizeof(response_1);
				memcpy(recv_buffer, response_1, recv_bytes);
			} break;
			case 1: {
				recv_bytes = sizeof(response_2);
				memcpy(recv_buffer, response_2, recv_bytes);
			} break;
			case 2: {
				recv_bytes = sizeof(response_3);
				memcpy(recv_buffer, response_3, recv_bytes);
			} break;
			case 3: {
				recv_bytes = sizeof(response_4);
				memcpy(recv_buffer, response_4, recv_bytes);
			} break;
			case 4: {
				recv_bytes = sizeof(response_5);
				memcpy(recv_buffer, response_5, recv_bytes);
			} break;
			case 5: {
				recv_bytes = sizeof(response_6);
				memcpy(recv_buffer, response_6, recv_bytes);
			} break;
		}

		printf("DECODING PACKET\n");
		uint8_t plaintext_buffer[1500] = {};
		uint64_t plaintext_size = 0;
		int ret = decode_server_packet(&ci, recv_buffer, recv_bytes, plaintext_buffer, &plaintext_size);
		if (ret == 0) {
			printf("failed to decode QUIC bytes\n");
			return false;
		}
		printf("decoded %d QUIC bytes\n", ret);

		state = parse_server_frames(&ci, plaintext_buffer, plaintext_size);
		if (state == Message_Failed) {
			printf("failed to process server frames!\n");
			return false;
		}
	}

	return true;
}

int main() {
	if (false) {
		printf("RUNNING SERVER TEST\n");
		return test_handshake();
	}

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

	Conn_Info ci = {
		.streams = stream_map_init(),
		.hostname = "localhost",
		.protocol = "h3",
		.dst_id     = dst_id,
		.dst_id_len = dst_id_len,
		.src_id     = src_id,
		.src_id_len = src_id_len,
	};
	gen_initial_keys(&ci);

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
	for (;;) {
		do {
			ssize_t recv_bytes = recvfrom(sd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
			if (recv_bytes < 0) {
				printf("failed to get response from server!\n");
				return 1;
			}
			if (recv_bytes == 0) {
				goto pkt_loop_end;
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
	}
	pkt_loop_end:
	printf("finished all packets in queue!\n");

	close(sd);
	return 0;
}
