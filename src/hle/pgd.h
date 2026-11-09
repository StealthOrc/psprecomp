#ifndef PSPRECOMP_PGD_H
#define PSPRECOMP_PGD_H

#include "aes.h"

#define PGD_HEADER_SIZE 0x90

typedef struct {
    uint32_t data_size;
    uint32_t data_offset;
    uint32_t block_size;
    uint32_t cached_offset;
    aes_ctx cipher;
    uint8_t counter_prefix[12];
    uint8_t block[];
} pgd_file;

/* Opens a fixed-key PGD container. The key can be NULL to derive it from the
 * authenticated header, as the PSP does for this type of container. */
pgd_file *pgd_open(const uint8_t header[PGD_HEADER_SIZE], const uint8_t *key,
                   uint64_t file_size);
void pgd_decrypt_block(pgd_file *pgd, uint32_t offset, size_t size);

#endif
