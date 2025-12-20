#pragma once

typedef struct {
	uint8_t *data;
	uint64_t len;
	uint64_t cap;
} Slice;

bool write_u8(Slice *s, uint8_t v) {
	if (s->len + sizeof(v) > s->cap) {
		panicf("write_u8 overflow: %llu > %llu\n", s->len + sizeof(v), s->cap);
	} 

	*(s->data + s->len) = v;
	s->len += sizeof(v);
	return true;
}

bool write_u16_be(Slice *s, uint16_t v) {
	if (s->len + sizeof(v) > s->cap) {
		panicf("write_u16_be overflow: %llu > %llu\n", s->len + sizeof(v), s->cap);
	} 

	uint16_t be_v = htons(v);
	memcpy(s->data + s->len, &be_v, sizeof(v));
	s->len += sizeof(v);
	return true;
}

bool write_u24_be(Slice *s, uint32_t v) {
	if (s->len + 3 > s->cap || v > 0xFFFFFF) {
		panicf("write_u24_be overflow: %llu > %llu || %u > 0xFFFFFF\n", s->len + 3, s->cap, v);
	}

	uint8_t be_v[3];
	be_v[0] = v >> 16;
	be_v[1] = v >> 8;
	be_v[2] = v;
	memcpy(s->data + s->len, be_v, 3);
	s->len += 3;
	return true;
}

bool write_u32_be(Slice *s, uint32_t v) {
	if (s->len + sizeof(v) > s->cap) {
		panicf("write_u32_be overflow: %llu > %llu\n", s->len + sizeof(v), s->cap);
	} 

	uint32_t be_v = htonl(v);
	memcpy(s->data + s->len, &be_v, sizeof(v));
	s->len += sizeof(v);
	return true;
}

bool write_u64_be(Slice *s, uint64_t v) {
	if (s->len + sizeof(v) > s->cap) {
		panicf("write_u64_be overflow: %llu > %llu\n", s->len + sizeof(v), s->cap);
	} 

	uint64_t be_v = htonll(v);
	memcpy(s->data + s->len, &be_v, sizeof(v));
	s->len += sizeof(v);
	return true;
}

bool write_data(Slice *s, uint8_t *data, size_t len) {
	if (s->len + len > s->cap) {
		panicf("write_data overflow: %llu > %llu\n", s->len + len, s->cap);
	} 

	memcpy(s->data + s->len, data, len);
	s->len += len;
	return true;
}

int varint_len(uint64_t v) {
	if (v > 0xC000000000000000) return 0;
	if (v < 0x40)               return 1;
	if (v < 0x4000)             return 2;
	if (v < 0x40000000)         return 4;
	return 8;
}

bool write_varint(Slice *s, uint64_t v) {
	// Value is too large to write the length bits
	if (v > 0xC000000000000000) {
		panicf("write_varint overflow: %llu > 0xC000000000000000\n", v);
	}

	int64_t rem_len = s->cap - s->len;

	if (v < 0x40 && rem_len >= 1) {
		(s->data + s->len)[0] = (uint8_t)v;
		s->len += 1;
		return true;
	}

	if (v < 0x4000 && rem_len >= 2) {
		(s->data + s->len)[0] = (uint8_t)((v >> 8) | 0x40);
		(s->data + s->len)[1] = (uint8_t)(v);
		s->len += 2;
		return true;
	}

	if (v < 0x40000000 && rem_len >= 4) {
		(s->data + s->len)[0] = (uint8_t)((v >> 24) | 0x80);
		(s->data + s->len)[1] = (uint8_t)(v >> 16);
		(s->data + s->len)[2] = (uint8_t)(v >> 8);
		(s->data + s->len)[3] = (uint8_t)(v);
		s->len += 4;
		return true;
	}

	if (rem_len >= 8) {
		(s->data + s->len)[0] = (uint8_t)((v >> 56) | 0xC0);
		(s->data + s->len)[1] = (uint8_t)(v >> 48);
		(s->data + s->len)[2] = (uint8_t)(v >> 40);
		(s->data + s->len)[3] = (uint8_t)(v >> 32);
		(s->data + s->len)[4] = (uint8_t)(v >> 24);
		(s->data + s->len)[5] = (uint8_t)(v >> 16);
		(s->data + s->len)[6] = (uint8_t)(v >> 8);
		(s->data + s->len)[7] = (uint8_t)(v);
		s->len += 8;
		return true;
	}

	panicf("write_varint fail?: %llu\n", v);
	return false;
}

uint8_t read_u8(Slice *s) {
	uint8_t out = 0;
	if (s->len + sizeof(out) > s->cap) {
		panicf("read_u8 overflow: %llu > %llu\n", s->len + sizeof(out), s->cap);
	}

	memcpy(&out, s->data + s->len, sizeof(out));
	s->len += sizeof(out);
	return out;
}

uint16_t read_u16_be(Slice *s) {
	uint16_t out = 0;
	if (s->len + sizeof(out) > s->cap) {
		panicf("read_u16_be overflow: %llu > %llu\n", s->len + sizeof(out), s->cap);
	}

	memcpy(&out, s->data + s->len, sizeof(out));
	s->len += sizeof(out);
	return ntohs(out);
}

uint32_t read_u24_be(Slice *s) {
	if (s->len + 3 > s->cap) {
		panicf("read_u24_be overflow: %llu > %llu\n", s->len + 3, s->cap);
	}

	uint8_t be_v[3];
	memcpy(be_v, s->data + s->len, 3);
	uint32_t out = be_v[0] << 16 | be_v[1] << 8 | be_v[2];

	s->len += 3;
	return out;
}

uint32_t read_u32_be(Slice *s) {
	uint32_t out = 0;
	if (s->len + sizeof(out) > s->cap) {
		panicf("read_u32_be overflow: %llu > %llu\n", s->len + sizeof(out), s->cap);
	}

	memcpy(&out, s->data + s->len, sizeof(out));
	s->len += sizeof(out);
	return ntohl(out);
}

uint64_t read_u64_be(Slice *s) {
	uint64_t out = 0;
	if (s->len + sizeof(out) > s->cap) {
		panicf("read_u64_be overflow: %llu > %llu\n", s->len + sizeof(out), s->cap);
	}

	memcpy(&out, s->data + s->len, sizeof(out));
	s->len += sizeof(out);
	return ntohll(out);
}

uint8_t *read_data(Slice *s, uint64_t len) {
	if (s->len + len > s->cap) {
		panicf("read_data overflow: %llu > %llu\n", s->len + len, s->cap);
	}

	uint8_t *out = s->data + s->len;
	s->len += len;
	return out;
}

uint64_t read_varint(Slice *s) {
	// Check for space for tag bits
	if (s->len + 1 > s->cap) {
		panicf("read_varint overflow: %llu > %llu\n", s->len + 1, s->cap);
	}

	uint8_t first_byte = *(s->data + s->len);
	uint32_t len = ((uint32_t)1u) << ((first_byte & 0xC0) >> 6);

	// Make sure we can read the whole value
	if (s->len + len > s->cap) {
		panicf("read_varint overflow: %llu > %llu\n", s->len + len, s->cap);
	}

	uint64_t val = (uint64_t)(first_byte & (~0xC0));
	for (int i = 1; i < len; i++) {
		val <<= 8ull;
		val += *(s->data + s->len + i);
	}

	s->len += len;
	return val;
}

uint64_t read_varint_len(Slice *s, uint64_t len) {
	if (s->len + len > s->cap) {
		panicf("read_varint_len overflow: %llu > %llu\n", s->len + len, s->cap);
	}

	uint64_t val = 0;
	for (int i = 0; i < len; i++) {
		val <<= 8ull;
		val += *(s->data + s->len + i);
	}

	s->len += len;
	return val;
}

void slice_seek(Slice *s, uint64_t idx) {
	if (idx > s->cap) {
		panicf("slice_seek overflow: %llu > %llu\n", idx, s->cap);
	}
	s->len = idx;
}
