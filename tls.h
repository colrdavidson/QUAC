#pragma once

enum {
	TLS_CipherSuite_AES128_GCM_SHA256        = 0x1301,
	TLS_CipherSuite_AES256_GCM_SHA384        = 0x1302,
	TLS_CipherSuite_CHACHA20_POLY1305_SHA256 = 0x1303,
};

enum {
	TLS_Group_X25519    = 0x001d,
	TLS_Group_secp256r1 = 0x0017,
	TLS_Group_secp384r1 = 0x0018,
};

enum {
	TLS_Signature_ECDSA_SECP256r1_SHA256 = 0x0403,
	TLS_Signature_RSA_PSS_RSAE_SHA256    = 0x0804,
	TLS_Signature_RSA_PKCS1_SHA256       = 0x0401,
	TLS_Signature_ECDSA_SECP384r1_SHA384 = 0x0503,
	TLS_Signature_RSA_PSS_RSAE_SHA384    = 0x0805,
	TLS_Signature_RSA_PKCS1_SHA384       = 0x0501,
	TLS_Signature_RSA_PSS_RSAE_SHA512    = 0x0806,
	TLS_Signature_RSA_PKCS1_SHA512       = 0x0601,
	TLS_Signature_RSA_PKCS1_SHA1         = 0x0201,
};

#define QUIC_TRANSPORT_PARAM(X)                             \
	X(TransportParam_OriginalDestinationConnectionID, 0x00) \
	X(TransportParam_MaxIdleTimeout,                  0x01) \
	X(TransportParam_StatelessResetToken,             0x02) \
	X(TransportParam_MaxUDPPayloadSize,               0x03) \
	X(TransportParam_InitialMaxData,                  0x04) \
	X(TransportParam_InitialMaxStreamDataBidiLocal,   0x05) \
	X(TransportParam_InitialMaxStreamDataBidiRemote,  0x06) \
	X(TransportParam_InitialMaxStreamDataUni,         0x07) \
	X(TransportParam_InitialMaxStreamsBidi,           0x08) \
	X(TransportParam_InitialMaxStreamsUni,            0x09) \
	X(TransportParam_AckDelayExponent,                0x0a) \
	X(TransportParam_MaxAckDelay,                     0x0b) \
	X(TransportParam_DisableActiveMigration,          0x0c) \
	X(TransportParam_PreferredAddress,                0x0d) \
	X(TransportParam_ActiveConnectionIDLimit,         0x0e) \
	X(TransportParam_InitialSourceConnectionID,       0x0f) \
	X(TransportParam_RetrySourceConnectionID,         0x10)

#define TLS_MESSAGE_TYPE(X)            \
	X(Message_ClientHello,          1) \
	X(Message_ServerHello,          2) \
	X(Message_NewSessionTicket,     4) \
	X(Message_EndOfEarlyData,       5) \
	X(Message_EncryptedExtensions,  8) \
	X(Message_Certificate,         11) \
	X(Message_CertificateRequest,  13) \
	X(Message_CertificateVerify,   15) \
	X(Message_Finished,            20) \
	X(Message_KeyUpdate,           24) \
	X(Message_MessageHash,        254)

#define TLS_EXTENSION_TYPE(X)              \
	X(Extension_ServerName,          0x00) \
	X(Extension_SupportedGroups,     0x0a) \
	X(Extension_SignatureAlgorithms, 0x0d) \
	X(Extension_ALPN,                0x10) \
	X(Extension_SupportedVersions,   0x2b) \
	X(Extension_PSKKeyExchangeModes, 0x2d) \
	X(Extension_KeyShare,            0x33) \
	X(Extension_QUICTransportParams, 0x39)

#define TLS_ALERT_DESC(X)                      \
	X(Alert_CloseNotify,                    0) \
	X(Alert_UnexpectedMessage,             10) \
	X(Alert_BadRecordMac,                  20) \
	X(Alert_RecordOverflow,                22) \
	X(Alert_HandshakeFailure,              40) \
	X(Alert_BadCertificate,                42) \
	X(Alert_UnsupportedCertificate,        43) \
	X(Alert_CertificateRevoked,            44) \
	X(Alert_CertificateExpired,            45) \
	X(Alert_CertificateUnknown,            46) \
	X(Alert_IllegalParameter,              47) \
	X(Alert_UnknownCA,                     48) \
	X(Alert_AccessDenied,                  49) \
	X(Alert_DecodeError,                   50) \
	X(Alert_DecryptError,                  51) \
	X(Alert_ProtocolVersion,               70) \
	X(Alert_InsufficientSecurity,          71) \
	X(Alert_InternalError,                 80) \
	X(Alert_InappropriateFallback,         86) \
	X(Alert_UserCancelled,                 90) \
	X(Alert_MissingExtension,             109) \
	X(Alert_UnsupportedExtension,         110) \
	X(Alert_UnrecognizedName,             112) \
	X(Alert_BadCertificateStatusResponse, 113) \
	X(Alert_UnknownPSKIdentity,           115) \
	X(Alert_CertificateRequired,          116) \
	X(Alert_NoApplicationProtocol,        120)

#define X(name, val) name = val,
typedef enum {
	TLS_ALERT_DESC(X)
} TLS_Alert_Desc;

typedef enum {
	TLS_EXTENSION_TYPE(X)
} TLS_Extension_Type;

typedef enum {
	TLS_MESSAGE_TYPE(X)
} TLS_Message_Type;

typedef enum {
	QUIC_TRANSPORT_PARAM(X)
} QUIC_Transport_Param;
#undef X

typedef struct {
	uint8_t original_dst_conn_id[20];
	uint8_t original_dst_conn_id_len;

	uint64_t max_idle_timeout;
	uint8_t stateless_reset_token[16];

	uint64_t max_udp_payload_size;

	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;

	uint8_t  ack_delay_exponent;
	uint16_t max_ack_delay;

	bool     disable_active_migration;

	uint8_t  preferred_ipv4_addr[4];
	uint16_t preferred_ipv4_port;

	uint8_t  preferred_ipv6_addr[16];
	uint16_t preferred_ipv6_port;

	uint64_t active_conn_id_limit;

	uint8_t initial_src_conn_id[20];
	uint8_t initial_src_conn_id_len;

	uint8_t retry_src_conn_id[20];
	uint8_t retry_src_conn_id_len;
} QUIC_Transport_Params;

typedef enum {
	TLS_State_Initial   = 0,
	TLS_State_Handshake,
} TLS_Conn_State;

typedef struct {
	Slice s;
	TLS_Conn_State state;
} TLS_State;

#define X(name, val) case name: return #name;
char *tls_alert_desc_to_str(TLS_Alert_Desc x) {
	switch (x) {
		TLS_ALERT_DESC(X)
		default: return "(unknown)";
	}
}
char *tls_extension_type_to_str(TLS_Extension_Type x) {
	switch (x) {
		TLS_EXTENSION_TYPE(X)
		default: return "(unknown)";
	}
}
char *tls_message_type_to_str(TLS_Message_Type x) {
	switch (x) {
		TLS_MESSAGE_TYPE(X)
		default: return "(unknown)";
	}
}
char *quic_transport_param_to_str(QUIC_Transport_Param x) {
	switch (x) {
		QUIC_TRANSPORT_PARAM(X)
		default: return "GREASE";
	}
}
#undef X

int build_client_hello(
		uint8_t *buffer, size_t buffer_size,
		char *hostname, size_t hostname_len,
		uint8_t *client_rand, size_t client_rand_len,
		uint8_t *client_public_key, size_t client_public_key_len,
		uint8_t *src_id, size_t src_id_len,
		QUIC_Transport_Params *params
	) {
	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	// TLS Client Hello
	write_u8(&s, Message_ClientHello);

	// skip the message size field for later
	s.len += 3;
	uint64_t msg_start = s.len;

	// TLS Client Version 1.2
	write_u16_be(&s, 0x0303);

	write_data(&s, client_rand, client_rand_len);

	// legacy session id
	write_u8(&s, 0x0);

	// Array of supported ciphers
	uint16_t supported_cipher_suites[] = {
		TLS_CipherSuite_AES128_GCM_SHA256,
		TLS_CipherSuite_AES256_GCM_SHA384,
		TLS_CipherSuite_CHACHA20_POLY1305_SHA256
	};
	write_u16_be(&s, sizeof(supported_cipher_suites));
	for (int i = 0; i < ELEM_COUNT(supported_cipher_suites); i++) {
		write_u16_be(&s, supported_cipher_suites[i]);
	}

	// No compression methods, per TLS 1.3
	write_u8(&s, 0x1);
	write_u8(&s, 0x0);

	// Array of extensions
	// skip over array len for now
	s.len += 2;
	uint64_t extension_arr_start = s.len;

	// Server Name Extension
	write_u16_be(&s, Extension_ServerName);

	write_u16_be(&s, hostname_len + 5);
	write_u16_be(&s, hostname_len + 3);
	write_u8(&s, 0);
	write_u16_be(&s, hostname_len);
	write_data(&s, (uint8_t *)hostname, hostname_len);

	// Supported Groups Extension
	write_u16_be(&s, Extension_SupportedGroups);

	uint16_t supported_groups[] = {
		TLS_Group_X25519,
		TLS_Group_secp256r1,
		TLS_Group_secp384r1
	};
	uint16_t supported_groups_data_len = sizeof(supported_groups) + 2;
	write_u16_be(&s, supported_groups_data_len);
	write_u16_be(&s, sizeof(supported_groups));
	for (int i = 0; i < ELEM_COUNT(supported_groups); i++) {
		write_u16_be(&s, supported_groups[i]);
	}

	// ALPN Extension
	write_u16_be(&s, Extension_ALPN);

	char alpn_data[] = "h3";
	int alpn_data_len = sizeof(alpn_data) - 1;

	write_u16_be(&s, alpn_data_len + 3);
	write_u16_be(&s, alpn_data_len + 1);
	write_u8(&s, alpn_data_len);
	write_data(&s, (uint8_t *)alpn_data, alpn_data_len);

	write_u16_be(&s, Extension_SignatureAlgorithms);

	uint16_t supported_signatures[] = {
		TLS_Signature_ECDSA_SECP256r1_SHA256,
		TLS_Signature_RSA_PSS_RSAE_SHA256,
		TLS_Signature_RSA_PKCS1_SHA256,
		TLS_Signature_ECDSA_SECP384r1_SHA384,
		TLS_Signature_RSA_PSS_RSAE_SHA384,
		TLS_Signature_RSA_PKCS1_SHA384,
		TLS_Signature_RSA_PSS_RSAE_SHA512,
		TLS_Signature_RSA_PKCS1_SHA512,
		TLS_Signature_RSA_PKCS1_SHA1
	};
	uint16_t supported_signatures_data_len = sizeof(supported_signatures) + 2;
	write_u16_be(&s, supported_signatures_data_len);
	write_u16_be(&s, sizeof(supported_signatures));
	for (int i = 0; i < ELEM_COUNT(supported_signatures); i++) {
		write_u16_be(&s, supported_signatures[i]);
	}

	// Key Share Extension
	write_u16_be(&s, Extension_KeyShare);

	write_u16_be(&s, client_public_key_len + 6);
	write_u16_be(&s, client_public_key_len + 4);
	write_u16_be(&s, 0x001d); // use x25519 for exchange
	write_u16_be(&s, client_public_key_len);
	write_data(&s, client_public_key, client_public_key_len);

	// PSK Key Exchange Modes Extension
	write_u16_be(&s, Extension_PSKKeyExchangeModes);
	write_u16_be(&s, 2);
	write_u8(&s, 1);
	write_u8(&s, 0x1); // PSK with ECDHE key establishment

	// Supported Versions Extension
	write_u16_be(&s, Extension_SupportedVersions);
	write_u16_be(&s, 3);
	write_u8(&s, 2);
	write_u16_be(&s, 0x0304); // TLS 1.3

	// Quic Transport Parameters Extension
	write_u16_be(&s, Extension_QUICTransportParams);

	// skip transport params length field for now
	s.len += 2;
	uint64_t transport_params_start = s.len;

	*params = (QUIC_Transport_Params){
		.max_udp_payload_size                = 0xFFF7,
		.initial_max_data                    = 0xA00000,
		.initial_max_stream_data_bidi_local  = 0x100000,
		.initial_max_stream_data_bidi_remote = 0x100000,
		.initial_max_stream_data_uni         = 0x100000,
		.initial_max_streams_bidi            = 10,
		.initial_max_streams_uni             = 10,
		.ack_delay_exponent                  = 3,
		.max_ack_delay                       = 25,
	};

	write_u8(&s, TransportParam_MaxUDPPayloadSize);
	write_u8(&s, varint_len(params->max_udp_payload_size));
	write_varint(&s, params->max_udp_payload_size);

	write_u8(&s, TransportParam_InitialMaxData);
	write_u8(&s, varint_len(params->initial_max_data));
	write_varint(&s, params->initial_max_data);

	write_u8(&s, TransportParam_InitialMaxStreamDataBidiLocal);
	write_u8(&s, varint_len(params->initial_max_stream_data_bidi_local));
	write_varint(&s, params->initial_max_stream_data_bidi_local);

	write_u8(&s, TransportParam_InitialMaxStreamDataBidiRemote);
	write_u8(&s, varint_len(params->initial_max_stream_data_bidi_remote));
	write_varint(&s, params->initial_max_stream_data_bidi_remote);

	write_u8(&s, TransportParam_InitialMaxStreamDataUni);
	write_u8(&s, varint_len(params->initial_max_stream_data_uni));
	write_varint(&s, params->initial_max_stream_data_uni);

	write_u8(&s, TransportParam_InitialMaxStreamsBidi);
	write_u8(&s, varint_len(params->initial_max_streams_bidi));
	write_varint(&s, params->initial_max_streams_bidi);

	write_u8(&s, TransportParam_InitialMaxStreamsUni);
	write_u8(&s, varint_len(params->initial_max_streams_uni));
	write_varint(&s, params->initial_max_streams_uni);

	write_u8(&s, TransportParam_AckDelayExponent);
	write_u8(&s, varint_len(params->ack_delay_exponent));
	write_varint(&s, params->ack_delay_exponent);

	write_u8(&s, TransportParam_MaxAckDelay);
	write_u8(&s, varint_len(params->max_ack_delay));
	write_varint(&s, params->max_ack_delay);

	write_u8(&s, TransportParam_InitialSourceConnectionID);
	write_u8(&s, src_id_len);
	write_data(&s, src_id, src_id_len);

	uint64_t transport_params_end = s.len;
	slice_seek(&s, transport_params_start - 2);
	uint64_t transport_params_len = transport_params_end - transport_params_start;
	write_u16_be(&s, transport_params_len);
	slice_seek(&s, transport_params_end);

	uint64_t extension_arr_end = s.len;
	slice_seek(&s, extension_arr_start - 2);
	uint64_t extension_arr_len = extension_arr_end - extension_arr_start;
	write_u16_be(&s, extension_arr_len);
	slice_seek(&s, extension_arr_end);

	// write the length into the header
	uint64_t msg_end = s.len;

	// jump back to fill out message length
	slice_seek(&s, msg_start - 3);
	write_u24_be(&s, msg_end - msg_start);

	// and back to the end
	slice_seek(&s, msg_end);

	return s.len;
}

bool parse_tls_server_hello(uint8_t *buffer, size_t buffer_size,
	uint8_t *server_public_key, size_t server_public_key_len,
	uint8_t *server_random) {
	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	uint16_t tls_version = read_u16_be(&s);
	if (tls_version != 0x0303) {
		printf("Invalid TLS version!\n");
		return false;
	}

	uint8_t *server_rand = read_data(&s, 32);
	uint8_t session_id = read_u8(&s);

	uint16_t cipher_suite = read_u16_be(&s);
	uint8_t compression_method = read_u8(&s);
	uint16_t extensions_len = read_u16_be(&s);

	uint64_t extensions_start = s.len;
	uint64_t extensions_end = extensions_start + extensions_len;

	while (s.len < extensions_end) {
		uint16_t extension_type = read_u16_be(&s);
		uint16_t extension_len  = read_u16_be(&s);

		switch ((TLS_Extension_Type)extension_type) {
			case Extension_SupportedVersions: {
				uint16_t version = read_u16_be(&s);
				if (version != 0x0304) {
					printf("Server doesn't support TLS 1.3! Got %x\n", version);
					return false;
				}
			} break;
			case Extension_KeyShare: {
				uint16_t key_exchange_type = read_u16_be(&s);
				uint16_t key_len = read_u16_be(&s);
				if (key_len != 32) {
					printf("unexpected server key returned! (0x%x, 0x%x)\n", key_exchange_type, key_len);
					return false;
				}

				uint8_t *key_data = read_data(&s, key_len);
				memcpy(server_public_key, key_data, key_len);
			} break;
			default: {
				printf("unhandled extension type: (%u) %s, len: %u\n", extension_type, tls_extension_type_to_str(extension_type), extension_len);
				return false;
			}
		}
	}

	memcpy(server_random, server_rand, 32);
	return true;
}

bool parse_tls_handshake(uint8_t *buffer, size_t buffer_size, QUIC_Transport_Params *params) {
	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	uint16_t extensions_len = read_u16_be(&s);
	uint64_t extensions_start = s.len;
	uint64_t extensions_end = extensions_start + extensions_len;

	while (s.len < extensions_end) {
		uint16_t extension_type = read_u16_be(&s);
		uint16_t extension_len  = read_u16_be(&s);
		uint64_t extension_end = s.len + extension_len;

		switch ((TLS_Extension_Type)extension_type) {
			case Extension_ServerName: {
				while (s.len < extension_end) {
					uint16_t list_entry_len = read_u16_be(&s);
					uint8_t list_entry_type = read_u8(&s);
					if (list_entry_type != 0x0) {
						printf("Unhandled server name list entry type %02x\n", list_entry_type);
						return false;
					}

					uint16_t hostname_len = read_u16_be(&s);
					uint8_t *hostname = read_data(&s, hostname_len);
				}
			} break;
			case Extension_ALPN: {
				uint16_t protocol_data_len = read_u16_be(&s);
				uint8_t protocol_name_len = read_u8(&s);
				uint8_t *protocol_name = read_data(&s, protocol_name_len);
			} break;
			case Extension_QUICTransportParams: {
				while (s.len < extension_end) {
					uint64_t field_type = read_varint(&s);
					uint64_t field_len = read_varint(&s);

					switch ((QUIC_Transport_Param)field_type) {
						case TransportParam_OriginalDestinationConnectionID: {
							uint8_t *dst_conn_id = read_data(&s, field_len);
							if (field_len > sizeof(params->original_dst_conn_id)) {
								printf("server-send dst conn id is too big!\n");
								return false;
							}

							memcpy(params->original_dst_conn_id, dst_conn_id, field_len);
							params->original_dst_conn_id_len = field_len;
						} break;
						case TransportParam_MaxIdleTimeout: {
							params->max_idle_timeout = read_varint(&s);
						} break;
						case TransportParam_StatelessResetToken: {
							if (field_len != 16) {
								printf("Stateless Reset Token is an invalid length?\n");
								return false;
							}

							uint8_t *stateless_reset_token = read_data(&s, field_len);
							memcpy(params->stateless_reset_token, stateless_reset_token, 16);
						} break;
						case TransportParam_MaxUDPPayloadSize: {
							params->max_udp_payload_size = read_varint(&s);
						} break;
						case TransportParam_InitialMaxData: {
							params->initial_max_data = read_varint(&s);
						} break;
						case TransportParam_InitialMaxStreamDataBidiLocal: {
							params->initial_max_stream_data_bidi_local = read_varint(&s);
						} break;
						case TransportParam_InitialMaxStreamDataBidiRemote: {
							params->initial_max_stream_data_bidi_remote = read_varint(&s);
						} break;
						case TransportParam_InitialMaxStreamDataUni: {
							params->initial_max_stream_data_uni = read_varint(&s);
						} break;
						case TransportParam_InitialMaxStreamsBidi: {
							params->initial_max_streams_bidi = read_varint(&s);
						} break;
						case TransportParam_InitialMaxStreamsUni: {
							params->initial_max_streams_uni = read_varint(&s);
						} break;
						case TransportParam_AckDelayExponent: {
							params->ack_delay_exponent = read_varint(&s);
						} break;
						case TransportParam_MaxAckDelay: {
							params->max_ack_delay = read_varint(&s);
						} break;
						case TransportParam_DisableActiveMigration: {
							params->disable_active_migration = true;
						} break;
						case TransportParam_ActiveConnectionIDLimit: {
							params->active_conn_id_limit = read_varint(&s);
						} break;
						case TransportParam_PreferredAddress: {
							printf("unhandled param (0x%04llx) %s\n", field_type, quic_transport_param_to_str(field_type));
							s.len += field_len;
						} break;
						case TransportParam_InitialSourceConnectionID: {
							uint8_t *src_conn_id = read_data(&s, field_len);
							if (field_len > sizeof(params->initial_src_conn_id)) {
								printf("server-send initial src conn id is too big!\n");
								return false;
							}

							memcpy(params->initial_src_conn_id, src_conn_id, field_len);
							params->initial_src_conn_id_len = field_len;
						} break;
						case TransportParam_RetrySourceConnectionID: {
							uint8_t *src_conn_id = read_data(&s, field_len);
							if (field_len > sizeof(params->retry_src_conn_id)) {
								printf("server-send retry src conn id is too big!\n");
								return false;
							}

							memcpy(params->retry_src_conn_id, src_conn_id, field_len);
							params->retry_src_conn_id_len = field_len;
						} break;
						default: {
							// Skip over GREASE
							s.len += field_len;
						}
					}
				}
			} break;
			default: {
				printf("unhandled extension type: (%u) %s, len: %u\n", extension_type, tls_extension_type_to_str(extension_type), extension_len);
				return false;
			}
		}
	}
	return true;
}

bool parse_tls_certificate(uint8_t *buffer, size_t buffer_size) {
	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	uint8_t request_ctx_len = read_u8(&s);
	uint32_t certs_len = read_u24_be(&s);

	uint64_t certs_end = s.len + certs_len;
	while (s.len < certs_end) {
		uint32_t cert_len = read_u24_be(&s);
		uint8_t *cert = read_data(&s, cert_len);

		uint16_t extension_data_len = read_u16_be(&s);
		if (extension_data_len != 0) {
			printf("unable to handle extension data!\n");
			return false;
		}
	}

	return true;
}

bool parse_tls_certificate_verify(uint8_t *buffer, size_t buffer_size) {
	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};

	uint16_t sig_algo = read_u16_be(&s);
	uint16_t sig_len = read_u16_be(&s);
	uint8_t *signature = read_data(&s, sig_len);

	return true;
}

Message_State tls_initial(
		TLS_State *tls, uint8_t *buffer, size_t buffer_size,
		EVP_MD_CTX *mdctx, uint8_t *server_public_key, size_t server_public_key_len,
		uint8_t *server_rand
	) {

	Slice s = {.data = buffer, .len = 0, .cap = buffer_size};
	uint64_t tls_msg_start = s.len;
	uint8_t  tls_msg_type = read_u8(&s);
	uint32_t tls_msg_size = read_u24_be(&s);

	switch ((TLS_Message_Type)tls_msg_type) {
		case Message_ServerHello: {
			update_sha256_sum(mdctx, s.data + tls_msg_start, buffer_size);

			uint8_t *tls_data = read_data(&s, tls_msg_size);
			if (!parse_tls_server_hello(
				tls_data, tls_msg_size,
				server_public_key, server_public_key_len,
				server_rand
			   )) {
				return Message_Failed;
			}
		} break;
		default: {
			printf("TLS Init failed!\n");
			return Message_Failed;
		}
	}

	return Message_Success;
}

Message_State tls_handshake(TLS_State *tls, uint8_t *buffer, size_t buffer_size, QUIC_Transport_Params *params) {
	// Handle fragment append now
	tls->s.cap = tls->s.len + buffer_size;
	tls->s.data = realloc(tls->s.data, tls->s.cap);
	memcpy(tls->s.data + tls->s.len, buffer, buffer_size);
	tls->s.len = 0;

	Slice *s = &tls->s;

	while (s->len < s->cap) {
		uint64_t tls_msg_start = s->len;
		uint8_t  tls_msg_type = read_u8(s);
		uint32_t tls_msg_size = read_u24_be(s);
		printf("msg start: %llu, type: %s, msg size: %u\n", tls_msg_start, tls_message_type_to_str(tls_msg_type), tls_msg_size);

		// Check for fragmentation, drop unnecessary-to-reparse bytes
		if (s->len + tls_msg_size > s->cap) {
			uint64_t rem_size = s->cap - tls_msg_start;
			printf("message fragmented! got %llu of %u bytes\n", rem_size, tls_msg_size);

			memmove(s->data, s->data + tls_msg_start, rem_size);
			s->len = rem_size;
			return Message_Fragmented;
		}

		uint64_t tls_msg_end = s->len + tls_msg_size;

		uint8_t *tls_blob = s->data + tls_msg_start;
		uint64_t tls_blob_size = tls_msg_end - tls_msg_start;

		switch ((TLS_Message_Type)tls_msg_type) {
			case Message_EncryptedExtensions: {
				uint8_t *tls_data = read_data(s, tls_msg_size);
				if (!parse_tls_handshake(tls_data, tls_msg_size, params)) {
					return Message_Failed;
				}
			} break;
			case Message_Certificate: {
				uint8_t *tls_data = read_data(s, tls_msg_size);
				if (!parse_tls_certificate(tls_data, tls_msg_size)) {
					return Message_Failed;
				}
			} break;
			case Message_CertificateVerify: {
				uint8_t *tls_data = read_data(s, tls_msg_size);
				if (!parse_tls_certificate_verify(tls_data, tls_msg_size)) {
					return Message_Failed;
				}
			} break;
			case Message_Finished: {
				uint8_t *verify_data = read_data(s, 32);
				return Message_Success;
			} break;
			default: {
				printf("unhandled TLS message type (%x) %s!\n", tls_msg_type, tls_message_type_to_str(tls_msg_type));
				return Message_Failed;
			}
		}
	}

	return Message_Fragmented;
}
