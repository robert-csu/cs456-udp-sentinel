#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "checkpoint.h"

#define CKPT_MAX_FILE (CKPT_HEADER_SIZE + CKPT_MAX_DATA + CKPT_CRC_SIZE)

// Calculate CRC32 checksum for the given data
uint32_t checkpoint_crc32(const void *data, size_t len) {
    const unsigned char *p = data;
    uint32_t crc = 0xFFFFFFFFu;
    for(size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for(int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

const char *checkpoint_strerror(ckpt_err_t err) {
    switch(err) {
    case CKPT_OK: return "ok";
    case CKPT_ERR_ARG: return "bad argument";
    case CKPT_ERR_IO: return "I/O error";
    case CKPT_ERR_MAGIC: return "bad magic";
    case CKPT_ERR_VERSION: return "unsupported version";
    case CKPT_ERR_LENGTH: return "bad length";
    case CKPT_ERR_CRC: return "CRC mismatch";
    }
    return "unknown error";
}

static long long wall_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void put_u32(unsigned char *buf, size_t *pos, uint32_t v) {
    for(int i = 0; i < 4; i++) {
        buf[(*pos)++] = (unsigned char)((v >> (8 * i)) & 0xFF);
    }
}

static void put_u64(unsigned char *buf, size_t *pos, uint64_t v) {
    for(int i = 0; i < 8; i++) {
        buf[(*pos)++] = (unsigned char)((v >> (8 * i)) & 0xFF);
    }
}

typedef struct {
    const unsigned char *p;
    size_t len;
    size_t pos;
    int bad;
} reader_t;

static uint32_t rd_u32(reader_t *r) {
    if(r->bad || r->len - r->pos < 4) {
        r->bad = 1;
        return 0;
    }
    uint32_t v = 0;
    for(int i = 0; i < 4; i++) {
        v |= (uint32_t)r->p[r->pos++] << (8 * i);
    }
    return v;
}

static uint64_t rd_u64(reader_t *r) {
    if(r->bad || r->len - r->pos < 8) {
        r->bad = 1;
        return 0;
    }
    uint64_t v = 0;
    for(int i = 0; i < 8; i++) {
        v |= (uint64_t)r->p[r->pos++] << (8 * i);
    }
    return v;
}

static void rd_bytes(reader_t *r, void *dst, size_t n) {
    if(r->bad || r->len - r->pos < n) {
        r->bad = 1;
        return;
    }
    memcpy(dst, r->p + r->pos, n);
    r->pos += n;
}

// Serialize the sentinel state into a buffer
static size_t serialize(const sentinel_state_t *s, unsigned char *out) {
    size_t pos = 0;
    int bl_count = s->blacklist.count;
    int tr_count = s->tracked_count;
    if(bl_count < 0 || bl_count > BL_MAX) {
        bl_count = 0;
    }
    if(tr_count < 0 || tr_count > MAX_TRACKED_IPS) {
        tr_count = 0;
    }

    put_u32(out, &pos, (uint32_t)bl_count);
    for(int i = 0; i < bl_count; i++) {
        memcpy(out + pos, s->blacklist.ips[i], SRC_IP_LEN);
        pos += SRC_IP_LEN;
    }

    put_u32(out, &pos, (uint32_t)tr_count);
    for(int i = 0; i < tr_count; i++) {
        const ip_track_t *t = &s->tracked[i];
        memcpy(out + pos, t->ip, SRC_IP_LEN);
        pos += SRC_IP_LEN;
        put_u32(out, &pos, (uint32_t)t->hits);
        put_u32(out, &pos, (uint32_t)t->ring_next);
        put_u32(out, &pos, (uint32_t)t->ring_count);
        for(int r = 0; r < HIT_RING; r++) {
            put_u64(out, &pos, (uint64_t)t->ring[r]);
        }
    }

    put_u64(out, &pos, (uint64_t)s->total_alerts);
    put_u64(out, &pos, (uint64_t)s->dropped_packets);
    put_u32(out, &pos, (uint32_t)s->inflight_valid);
    put_u32(out, &pos, (uint32_t)s->inflight_hash);
    return pos;
}

static int field_is_ip(const char *field) {
    if(memchr(field, '\0', SRC_IP_LEN) == NULL) {
        return 0;
    }
    struct in_addr addr;
    return inet_pton(AF_INET, field, &addr) == 1;
}

// Deserialize the sentinel state from a buffer
static int deserialize(const unsigned char *data, size_t len, sentinel_state_t *out) {
    reader_t r = {.p = data, .len = len, .pos = 0, .bad = 0};

    uint32_t bl_count = rd_u32(&r);
    if(r.bad || bl_count > BL_MAX) {
        return -1;
    }
    for(uint32_t i = 0; i < bl_count; i++) {
        rd_bytes(&r, out->blacklist.ips[i], SRC_IP_LEN);
        if(r.bad || !field_is_ip(out->blacklist.ips[i])) {
            return -1;
        }
    }
    out->blacklist.count = (int)bl_count;

    uint32_t tr_count = rd_u32(&r);
    if(r.bad || tr_count > MAX_TRACKED_IPS) {
        return -1;
    }
    for(uint32_t i = 0; i < tr_count; i++) {
        ip_track_t *t = &out->tracked[i];
        rd_bytes(&r, t->ip, SRC_IP_LEN);
        uint32_t hits = rd_u32(&r);
        uint32_t ring_next = rd_u32(&r);
        uint32_t ring_count = rd_u32(&r);
        for(int k = 0; k < HIT_RING; k++) {
            t->ring[k] = (long long)rd_u64(&r);
        }
        if(r.bad || !field_is_ip(t->ip) || hits > INT_MAX || ring_next >= HIT_RING || ring_count > HIT_RING) {
            return -1;
        }
        t->hits = (int)hits;
        t->ring_next = (int)ring_next;
        t->ring_count = (int)ring_count;
    }
    out->tracked_count = (int)tr_count;

    out->total_alerts = (long long)rd_u64(&r);
    out->dropped_packets = (long long)rd_u64(&r);
    uint32_t inflight_valid = rd_u32(&r);
    out->inflight_hash = rd_u32(&r);
    if(r.bad || inflight_valid > 1 || r.pos != len) {
        return -1;
    }
    out->inflight_valid = (int)inflight_valid;
    return 0;
}

// Read and validate a checkpoint file
static ckpt_err_t read_validated(const char *path, unsigned char **buf, size_t *size, uint32_t *epoch) {
    FILE *f = fopen(path, "rb");
    if(!f) {
        return CKPT_ERR_IO;
    }
    unsigned char *b = malloc(CKPT_MAX_FILE + 1);
    if(!b) {
        fclose(f);
        return CKPT_ERR_IO;
    }
    size_t n = fread(b, 1, CKPT_MAX_FILE + 1, f);
    int read_failed = ferror(f);
    fclose(f);
    if(read_failed) {
        free(b);
        return CKPT_ERR_IO;
    }

    ckpt_err_t err = CKPT_OK;
    if(n < CKPT_HEADER_SIZE + CKPT_CRC_SIZE || n > CKPT_MAX_FILE) {
        err = CKPT_ERR_LENGTH;
    }
    else if(memcmp(b, CKPT_MAGIC, 4) != 0) {
        err = CKPT_ERR_MAGIC;
    }
    else {
        reader_t r = {.p = b + 4, .len = CKPT_HEADER_SIZE - 4, .pos = 0, .bad = 0};
        uint32_t version = rd_u32(&r);
        uint32_t ep = rd_u32(&r);
        uint32_t data_len = rd_u32(&r);
        if(version != CKPT_VERSION) {
            err = CKPT_ERR_VERSION;
        }
        else if((uint64_t)CKPT_HEADER_SIZE + data_len + CKPT_CRC_SIZE != n || ep > INT_MAX) {
            err = CKPT_ERR_LENGTH;
        }
        else {
            reader_t c = {.p = b + n - CKPT_CRC_SIZE, .len = CKPT_CRC_SIZE, .pos = 0, .bad = 0};
            if(rd_u32(&c) != checkpoint_crc32(b, n - CKPT_CRC_SIZE)) {
                err = CKPT_ERR_CRC;
            }
            else {
                *epoch = ep;
            }
        }
    }

    if(err != CKPT_OK) {
        free(b);
        return err;
    }
    *buf = b;
    *size = n;
    return CKPT_OK;
}

static int write_all(int fd, const unsigned char *buf, size_t n) {
    size_t done = 0;
    while(done < n) {
        ssize_t w = write(fd, buf + done, n - done);
        if(w < 0) {
            if(errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t)w;
    }
    return 0;
}

// Create the parent directory of a file path if one is missing
static void make_parent_dir(const char *path) {
    char dir[512];
    size_t len = strlen(path);
    if(len >= sizeof dir) {
        return;
    }
    memcpy(dir, path, len + 1);
    char *slash = strrchr(dir, '/');
    if(slash && slash != dir) {
        *slash = '\0';
        mkdir(dir, 0755);
    }
}

static void sync_parent_dir(const char *path) {
    char dir[512];
    size_t len = strlen(path);
    if(len >= sizeof dir) {
        return;
    }
    memcpy(dir, path, len + 1);
    char *slash = strrchr(dir, '/');
    const char *d = ".";
    if(slash) {
        *slash = '\0';
        d = slash == dir ? "/" : dir;
    }
    int fd = open(d, O_RDONLY);
    if(fd >= 0) {
        fsync(fd);
        close(fd);
    }
}

// Save the current state to a checkpoint file
ckpt_err_t checkpoint_save(sentinel_state_t *s, const char *path, const char *tmp, const char *prev) {
    if(!s || !path || !tmp || !prev) {
        return CKPT_ERR_ARG;
    }
    unsigned char *buf = malloc(CKPT_MAX_FILE);
    if(!buf) {
        return CKPT_ERR_IO;
    }
    pthread_mutex_lock(&s->lock);
    size_t data_len = serialize(s, buf + CKPT_HEADER_SIZE);
    uint32_t epoch = (uint32_t)(s->epoch < 0 ? 0 : s->epoch);
    pthread_mutex_unlock(&s->lock);

    memcpy(buf, CKPT_MAGIC, 4);
    size_t pos = 4;
    put_u32(buf, &pos, CKPT_VERSION);
    put_u32(buf, &pos, epoch);
    put_u32(buf, &pos, (uint32_t)data_len);
    pos = CKPT_HEADER_SIZE + data_len;
    put_u32(buf, &pos, checkpoint_crc32(buf, CKPT_HEADER_SIZE + data_len));

    make_parent_dir(path);

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(fd < 0) {
        free(buf);
        return CKPT_ERR_IO;
    }
    if(write_all(fd, buf, pos) != 0 || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        free(buf);
        return CKPT_ERR_IO;
    }
    close(fd);
    free(buf);

    unsigned char *old = NULL;
    size_t old_size = 0;
    uint32_t old_epoch = 0;
    if(read_validated(path, &old, &old_size, &old_epoch) == CKPT_OK) {
        free(old);
        unlink(prev);
        if(link(path, prev) != 0) {
            // no hard links on this file system: move it instead, path is rewritten right below
            rename(path, prev);
        }
    }

    if(rename(tmp, path) != 0) {
        unlink(tmp);
        return CKPT_ERR_IO;
    }
    sync_parent_dir(path);
    return CKPT_OK;
}

ckpt_err_t checkpoint_load_file(sentinel_state_t *s, const char *path) {
    if(!s || !path) {
        return CKPT_ERR_ARG;
    }
    unsigned char *buf = NULL;
    size_t size = 0;
    uint32_t epoch = 0;
    ckpt_err_t err = read_validated(path, &buf, &size, &epoch);
    if(err != CKPT_OK) {
        return err;
    }

    sentinel_state_t *tmp = calloc(1, sizeof *tmp);
    if(!tmp) {
        free(buf);
        return CKPT_ERR_IO;
    }
    if(deserialize(buf + CKPT_HEADER_SIZE, size - CKPT_HEADER_SIZE - CKPT_CRC_SIZE, tmp) != 0) {
        free(tmp);
        free(buf);
        return CKPT_ERR_LENGTH;
    }
    free(buf);

    pthread_mutex_lock(&s->lock);
    s->blacklist = tmp->blacklist;
    memcpy(s->tracked, tmp->tracked, sizeof s->tracked);
    s->tracked_count = tmp->tracked_count;
    s->total_alerts = tmp->total_alerts;
    s->dropped_packets = tmp->dropped_packets;
    s->epoch = (int)epoch;
    s->inflight_valid = tmp->inflight_valid;
    s->inflight_hash = tmp->inflight_hash;
    pthread_mutex_unlock(&s->lock);

    free(tmp);
    return CKPT_OK;
}

ckpt_source_t checkpoint_load(sentinel_state_t *s, const blacklist_t *base, const char *path, const char *prev) {
    if(!s || !path || !prev) {
        return CKPT_SRC_ERR;
    }
    if(state_init(s, base) != 0) {
        return CKPT_SRC_ERR;
    }

    ckpt_source_t source = CKPT_SRC_BASE;
    const char *why_cur = NULL;
    const char *why_prev = NULL;

    ckpt_err_t err = checkpoint_load_file(s, path);
    if(err == CKPT_OK) {
        return CKPT_SRC_CURRENT;
    }
    if(access(path, F_OK) == 0) {
        why_cur = checkpoint_strerror(err);
    }

    err = checkpoint_load_file(s, prev);
    if(err == CKPT_OK) {
        source = CKPT_SRC_PREV;
    }
    else if(access(prev, F_OK) == 0) {
        why_prev = checkpoint_strerror(err);
    }

    const char *using_what = source == CKPT_SRC_PREV ? "checkpoint.prev" : "base blacklist";
    if(why_cur && why_prev) {
        fprintf(stderr, "[%lld] WARN checkpoint rejected: %s; checkpoint.prev rejected: %s, using %s\n", wall_ms(), why_cur, why_prev, using_what);
    }
    else if(why_cur) {
        fprintf(stderr, "[%lld] WARN checkpoint rejected: %s, using %s\n", wall_ms(), why_cur, using_what);
    }
    else if(why_prev) {
        fprintf(stderr, "[%lld] WARN checkpoint.prev rejected: %s, using %s\n", wall_ms(), why_prev, using_what);
    }
    else if(source == CKPT_SRC_BASE) {
        fprintf(stderr, "[%lld] INFO no checkpoint found, using base blacklist\n", wall_ms());
    }
    return source;
}
