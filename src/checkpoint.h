#ifndef CHECKPOINT_H
#define CHECKPOINT_H

#include <stddef.h>
#include <stdint.h>
#include "state.h"

#define CKPT_MAGIC "SNTL" // Sentinel checkpoint magic number
#define CKPT_VERSION 1 // Checkpoint version
#define CKPT_HEADER_SIZE 16 // Size of the checkpoint header
#define CKPT_CRC_SIZE 4 // Size of the CRC field

#define CKPT_MAX_DATA (4 + BL_MAX * SRC_IP_LEN + 4 + MAX_TRACKED_IPS * (SRC_IP_LEN + 12 + HIT_RING * 8) + 8 + 8 + 4 + 4) // Maximum size of the checkpoint data

typedef enum {
    CKPT_OK = 0,
    CKPT_ERR_ARG = -1, // NULL argument
    CKPT_ERR_IO = -2, // file could not be opened, read or written
    CKPT_ERR_MAGIC = -3, // file does not start with the magic
    CKPT_ERR_VERSION = -4, // unsupported format version
    CKPT_ERR_LENGTH = -5, // file too short or long, or the data inside is malformed
    CKPT_ERR_CRC = -6 // checksum does not match
} ckpt_err_t;

typedef enum {
    CKPT_SRC_ERR = -1, // NULL argument
    CKPT_SRC_CURRENT = 0, // state came from the current checkpoint
    CKPT_SRC_PREV = 1, // state came from the previous checkpoint
    CKPT_SRC_BASE = 2 // no usable checkpoint, started from the base blacklist
} ckpt_source_t;

uint32_t checkpoint_crc32(const void *data, size_t len);

const char *checkpoint_strerror(ckpt_err_t err);

ckpt_err_t checkpoint_save(sentinel_state_t *s, const char *path, const char *tmp, const char *prev);

ckpt_err_t checkpoint_load_file(sentinel_state_t *s, const char *path);

ckpt_source_t checkpoint_load(sentinel_state_t *s, const blacklist_t *base, const char *path, const char *prev);

#endif