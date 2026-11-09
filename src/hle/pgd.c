/* Fixed-key PSP PGD containers (AMCTRL). The KIRK key slots and PGD format
 * are documented by PPSSPP's libkirk. The runtime uses its own AES and CMAC.
 */
#include "pgd.h"
#include "cmac.h"
#include "keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
    uint8_t mac_key[16], seed_key[16], stream_key[16], header_key[16];
    uint8_t mac_mask[16], seed_input_mask[16], seed_output_mask[12];
} material;

/* The guest runs on one scheduler thread. Load once, on demand, and report
 * a missing or malformed entry once even if the game retries the request. */
static int load_material(void) {
    static int state;
    if (state) return state > 0;
    state = -1;
    key_store *keys = malloc(sizeof *keys);
    if (!keys) {
        fprintf(stderr, "psprecomp: PGD: could not allocate key store\n");
        return 0;
    }
    if (keys_load(keys, NULL) != 0) {
        fprintf(stderr, "psprecomp: PGD: no key file found; set PSPRECOMP_KEYS or supply keys/psp_keys.txt\n");
        free(keys);
        return 0;
    }

    const struct { const char *name; uint8_t *bytes; size_t size; } entries[] = {
        { "kirk.38", material.mac_key, sizeof material.mac_key },
        { "kirk.39", material.seed_key, sizeof material.seed_key },
        { "kirk.63", material.stream_key, sizeof material.stream_key },
        { "pgd.dnas", material.header_key, sizeof material.header_key },
        { "pgd.mac_mask", material.mac_mask, sizeof material.mac_mask },
        { "pgd.seed_input_mask", material.seed_input_mask, sizeof material.seed_input_mask },
        { "pgd.seed_output_mask", material.seed_output_mask, sizeof material.seed_output_mask },
    };
    for (size_t i = 0; i < sizeof entries / sizeof entries[0]; i++) {
        char error[640];
        const uint8_t *bytes = keys_require(keys, entries[i].name, entries[i].size, error, sizeof error);
        if (!bytes) {
            fprintf(stderr, "psprecomp: PGD: %s\n", error);
            free(keys);
            return 0;
        }
        memcpy(entries[i].bytes, bytes, entries[i].size);
    }
    free(keys);
    state = 1;
    return 1;
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* Reverse the final AMCTRL MAC transforms to recover the version key. */
static void mac_version_key(const aes_ctx *cipher, const aes_ctx *mac,
                            const uint8_t *header, size_t size, uint8_t version[16]) {
    uint8_t tag[16];
    memcpy(tag, header + size, sizeof tag);
    if (cipher) aes_decrypt_block(cipher, tag, tag);
    aes_decrypt_block(mac, tag, tag);
    aes_cmac(material.mac_key, 128, header, size, version);
    for (size_t i = 0; i < sizeof tag; i++) version[i] ^= tag[i] ^ material.mac_mask[i];
}

static void counter_prefix(uint8_t prefix[12], const uint8_t data_key[16],
                           const uint8_t version[16]) {
    aes_ctx cipher;
    uint8_t seed[16];
    for (size_t i = 0; i < sizeof seed; i++) seed[i] = data_key[i] ^ version[i] ^ material.seed_input_mask[i];
    aes_init(&cipher, material.seed_key, 128);
    aes_decrypt_block(&cipher, seed, seed);
    for (size_t i = 0; i < 12; i++) prefix[i] = seed[i] ^ material.seed_output_mask[i];
}

static void set_counter(uint8_t counter[16], uint32_t n) {
    counter[12] = (uint8_t)n;
    counter[13] = (uint8_t)(n >> 8);
    counter[14] = (uint8_t)(n >> 16);
    counter[15] = (uint8_t)(n >> 24);
}

static void decrypt(const aes_ctx *cipher, const uint8_t prefix[12],
                    uint8_t *data, size_t size, uint32_t offset) {
    uint8_t previous[16] = {0};
    uint8_t counter[16];
    memcpy(counter, prefix, 12);
    uint32_t n = offset / 16;
    if (n != 0) {
        set_counter(counter, n);
        memcpy(previous, counter, sizeof previous);
    }

    /* The stream is CBC decryption of consecutive counters with a zero IV
     * only at the start. An arbitrary read uses the previous counter as IV. */
    while (size != 0) {
        uint8_t stream[16];
        set_counter(counter, ++n);
        aes_decrypt_block(cipher, counter, stream);
        for (size_t i = 0; i < sizeof stream; i++) data[i] ^= stream[i] ^ previous[i];
        memcpy(previous, counter, sizeof previous);
        data += sizeof stream;
        size -= sizeof stream;
    }
}

pgd_file *pgd_open(const uint8_t header[PGD_HEADER_SIZE], const uint8_t *key,
                   uint64_t file_size) {
    if (memcmp(header, "\0PGD", 4) != 0 || read_le32(header + 8) != 1) return NULL;
    if (!load_material()) return NULL;

    aes_ctx mac, cipher;
    aes_init(&mac, material.mac_key, 128);
    aes_init(&cipher, material.stream_key, 128);
    const aes_ctx *tag_cipher = read_le32(header + 4) > 1 ? &cipher : NULL;
    uint8_t version[16];
    mac_version_key(tag_cipher, &mac, header, 0x80, version);
    if (!cmac_equal(version, material.header_key)) return NULL;
    mac_version_key(tag_cipher, &mac, header, 0x70, version);
    if (key && !cmac_equal(version, key)) return NULL;

    uint8_t descriptor[0x30], prefix[12];
    memcpy(descriptor, header + 0x30, sizeof descriptor);
    counter_prefix(prefix, header + 0x10, version);
    decrypt(&cipher, prefix, descriptor, sizeof descriptor, 0);
    uint32_t data_size = read_le32(descriptor + 0x14);
    uint32_t block_size = read_le32(descriptor + 0x18);
    uint32_t data_offset = read_le32(descriptor + 0x1C);
    uint64_t aligned_size = ((uint64_t)data_size + 15) & ~(uint64_t)15;
    if (block_size < 16 || block_size > 0x100000 || (block_size & (block_size - 1)) ||
        data_offset < PGD_HEADER_SIZE || data_offset + aligned_size > file_size) return NULL;

    pgd_file *pgd = malloc(sizeof *pgd + block_size);
    if (!pgd) return NULL;
    pgd->data_size = data_size;
    pgd->data_offset = data_offset;
    pgd->block_size = block_size;
    pgd->cached_offset = UINT32_MAX;
    pgd->cipher = cipher;
    counter_prefix(pgd->counter_prefix, descriptor, version);
    return pgd;
}

void pgd_decrypt_block(pgd_file *pgd, uint32_t offset, size_t size) {
    decrypt(&pgd->cipher, pgd->counter_prefix, pgd->block, size, offset);
    pgd->cached_offset = offset;
}
