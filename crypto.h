#pragma once

void hdkf_extract(uint8_t out[32], uint8_t *salt, size_t salt_size, uint8_t *key, size_t key_size) {
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);

	OSSL_PARAM params[5];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256));
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, key_size);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_size);
	params[3] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, (int[]){ EVP_KDF_HKDF_MODE_EXTRACT_ONLY });
	params[4] = OSSL_PARAM_construct_end();

	EVP_KDF_derive(kctx, out, 32, params);

	EVP_KDF_CTX_free(kctx);
	EVP_KDF_free(kdf);
}

void hdkf_expand_label(uint8_t *out, size_t out_size, uint8_t key[32], char *label) {
	char prefix[] = "tls13 ";
	uint16_t prefix_len = sizeof(prefix) - 1;
	uint16_t label_len = strlen(label);
	uint8_t full_label_len = prefix_len + label_len;
	uint16_t hash_len = htons(out_size);

	int hkdf_label_len = 0;
	char hkdf_label[80] = {};
	memcpy(hkdf_label + hkdf_label_len, &hash_len, sizeof(hash_len)); hkdf_label_len += sizeof(hash_len);
	memcpy(hkdf_label + hkdf_label_len, &full_label_len, sizeof(full_label_len)); hkdf_label_len += sizeof(full_label_len);
	memcpy(hkdf_label + hkdf_label_len, prefix, prefix_len); hkdf_label_len += prefix_len;
	memcpy(hkdf_label + hkdf_label_len, label,  label_len);  hkdf_label_len += label_len;
	*(hkdf_label + hkdf_label_len) = 0; hkdf_label_len += 1;
	*(hkdf_label + hkdf_label_len) = 1; hkdf_label_len += 1;

	uint8_t out_buf[32] = {};
	uint32_t out_buf_size;
	HMAC(EVP_sha256(), key, 32, (const uint8_t *)hkdf_label, hkdf_label_len, out_buf, &out_buf_size);

	// truncate hash output to buffer
	memcpy(out, out_buf, out_size);
}

void encrypt_buffer(uint8_t *out_buffer, uint8_t *buffer, size_t buffer_size, uint8_t key[32], uint8_t iv[12], uint8_t aead[16], uint8_t *nonce, uint8_t *pkt_hdr) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

	int byte_count = 0;
	EVP_EncryptUpdate(ctx, NULL, &byte_count, pkt_hdr, 24);
	EVP_EncryptUpdate(ctx, out_buffer, &byte_count, buffer, buffer_size);
	EVP_EncryptFinal_ex(ctx, out_buffer + byte_count, &byte_count);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, aead);

	EVP_CIPHER_CTX_free(ctx);
	return;
}

void generate_mask(uint8_t *payload_mask, uint8_t *sample, uint8_t hp_key[16]) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp_key, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, false);

	int byte_count = 0;
	EVP_EncryptUpdate(ctx, payload_mask, &byte_count, sample, 16);
	EVP_EncryptFinal_ex(ctx, payload_mask + byte_count, &byte_count);

	EVP_CIPHER_CTX_free(ctx);
}

void generate_public_key(uint8_t private_key[32], uint8_t public_key[32]) {
	EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);

	size_t pub_key_len = 32;
	EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_key_len);
	EVP_PKEY_free(pkey);
}

bool decrypt_buffer(uint8_t *out_buffer, uint8_t *buffer, size_t buffer_size, uint8_t key[32], uint8_t iv[12], uint8_t aead[16], uint8_t *nonce, uint8_t *pkt_hdr) {
	//return crypto_aead_aes256gcm_decrypt_detached(out_buffer, NULL, buffer, buffer_size, aead, NULL, 0, nonce, key) == 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

	int byte_count = 0;
	EVP_DecryptUpdate(ctx, NULL, &byte_count, pkt_hdr, 21);
	EVP_DecryptUpdate(ctx, out_buffer, &byte_count, buffer, buffer_size);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, aead);

	int final = EVP_DecryptFinal_ex(ctx, out_buffer + byte_count, &byte_count);

	EVP_CIPHER_CTX_free(ctx);

	return final > 0;
}
