/*
 * chez_ssh_shim.c — SSH agent implementation for Chez Scheme
 *
 * Implements the SSH agent protocol (draft-miller-ssh-agent) with Ed25519
 * key support via OpenSSL. Private keys are stored in mlock'd memory and
 * never cross the FFI boundary — signing happens entirely in C.
 *
 * Provides:
 *   - OpenSSH private key parser (base64 + binary format)
 *   - Secure key storage (mlock, MADV_DONTDUMP, explicit_bzero)
 *   - SSH agent protocol handler (identities, signing)
 *   - Unix domain socket server (background pthread)
 *
 * Link with: -lcrypto -lpthread
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <termios.h>
#include <fcntl.h>
#include "bcrypt_pbkdf.h"
#ifndef CHEZ_SSH_NO_OPENSSL
#include <openssl/evp.h>
#else
/* Standalone ed25519 — defined in ed25519-standalone.c */
int ed25519_sign_standalone(const uint8_t *seed,
                             const uint8_t *data, size_t datalen,
                             uint8_t *sig_out);
int ed25519_derive_pubkey_standalone(const uint8_t *seed, uint8_t *pubkey_out);
#endif

/* ========== Constants ========== */

#define MAX_KEYS        16
#define MAX_COMMENT     256
#define MAX_MSG         262144   /* 256 KB max agent message */
#define ED25519_SEED    32
#define ED25519_PUB     32
#define ED25519_SIG     64

/* SSH agent protocol message types */
#define SSH_AGENT_FAILURE                5
#define SSH_AGENT_SUCCESS                6
#define SSH_AGENTC_REQUEST_IDENTITIES    11
#define SSH_AGENT_IDENTITIES_ANSWER      12
#define SSH_AGENTC_SIGN_REQUEST          13
#define SSH_AGENT_SIGN_RESPONSE          14
#define SSH_AGENTC_ADD_IDENTITY          17
#define SSH_AGENTC_REMOVE_IDENTITY       18
#define SSH_AGENTC_REMOVE_ALL_IDENTITIES 19

/* ========== Key Storage ========== */

typedef struct {
    uint8_t seed[ED25519_SEED];     /* 32-byte Ed25519 private seed */
    uint8_t pubkey[ED25519_PUB];    /* 32-byte Ed25519 public key */
    char    comment[MAX_COMMENT];
    int     active;
} ssh_key_t;

/* Page-aligned for mlock granularity */
static ssh_key_t _keys[MAX_KEYS] __attribute__((aligned(4096)));
static int _key_count = 0;
static int _keys_hardened = 0;

/* Harden key storage: pin in RAM, exclude from core dumps */
static void harden_keys(void) {
    if (_keys_hardened) return;
    _keys_hardened = 1;
    mlock(_keys, sizeof(_keys));
    madvise(_keys, sizeof(_keys), MADV_DONTDUMP);
}

/* ========== Socket State ========== */

static int _agent_fd = -1;                      /* listening socket */
static char _agent_path[256] = {0};              /* socket file path */
static char _agent_dir[256] = {0};               /* socket directory */
static volatile int _agent_running = 0;
static pthread_t _agent_thread;
static int _agent_wakeup_pipe[2] = {-1, -1};     /* for clean shutdown */

/* ========== Base64 Decode ========== */

static const uint8_t b64_table[256] = {
    ['A']=0,  ['B']=1,  ['C']=2,  ['D']=3,  ['E']=4,  ['F']=5,
    ['G']=6,  ['H']=7,  ['I']=8,  ['J']=9,  ['K']=10, ['L']=11,
    ['M']=12, ['N']=13, ['O']=14, ['P']=15, ['Q']=16, ['R']=17,
    ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25,
    ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
    ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37,
    ['m']=38, ['n']=39, ['o']=40, ['p']=41, ['q']=42, ['r']=43,
    ['s']=44, ['t']=45, ['u']=46, ['v']=47, ['w']=48, ['x']=49,
    ['y']=50, ['z']=51,
    ['0']=52, ['1']=53, ['2']=54, ['3']=55, ['4']=56, ['5']=57,
    ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['+']= 62, ['/']= 63,
};

static int is_b64_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

/*
 * base64_decode — Decode base64 data, skipping whitespace.
 * Returns decoded length, or -1 on error.
 */
static int base64_decode(const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t maxout) {
    size_t oi = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < inlen; i++) {
        uint8_t c = in[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        if (!is_b64_char(c)) return -1;
        acc = (acc << 6) | b64_table[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (oi >= maxout) return -1;
            out[oi++] = (acc >> bits) & 0xFF;
        }
    }
    return (int)oi;
}

/* ========== SSH Wire Format Helpers ========== */

/* Read big-endian uint32 from buffer. Returns -1 if not enough data. */
static int read_uint32(const uint8_t *buf, size_t len, size_t *pos, uint32_t *val) {
    if (*pos + 4 > len) return -1;
    *val = ((uint32_t)buf[*pos] << 24) | ((uint32_t)buf[*pos+1] << 16) |
           ((uint32_t)buf[*pos+2] << 8) | buf[*pos+3];
    *pos += 4;
    return 0;
}

/* Read SSH string (uint32 length + bytes). Returns pointer and length. */
static int read_string(const uint8_t *buf, size_t len, size_t *pos,
                       const uint8_t **data, uint32_t *dlen) {
    uint32_t slen;
    if (read_uint32(buf, len, pos, &slen) < 0) return -1;
    if (*pos + slen > len) return -1;
    *data = buf + *pos;
    *dlen = slen;
    *pos += slen;
    return 0;
}

/* Write big-endian uint32 */
static void write_uint32(uint8_t *buf, size_t *pos, uint32_t val) {
    buf[*pos]   = (val >> 24) & 0xFF;
    buf[*pos+1] = (val >> 16) & 0xFF;
    buf[*pos+2] = (val >> 8)  & 0xFF;
    buf[*pos+3] =  val        & 0xFF;
    *pos += 4;
}

/* Write SSH string (uint32 length + bytes) */
static void write_string(uint8_t *buf, size_t *pos,
                         const uint8_t *data, uint32_t dlen) {
    write_uint32(buf, pos, dlen);
    memcpy(buf + *pos, data, dlen);
    *pos += dlen;
}

/* ========== OpenSSH Key Parser ========== */

static const char OPENSSH_MAGIC[] = "openssh-key-v1\0";
#define OPENSSH_MAGIC_LEN 15

/*
 * AES-256-CTR decryption — used to decrypt OpenSSH encrypted private keys.
 * OpenSSL path uses EVP, standalone path uses a minimal AES implementation.
 */
#ifndef CHEZ_SSH_NO_OPENSSL
static int aes256_ctr_decrypt(const uint8_t *key, const uint8_t *iv,
                               const uint8_t *input, size_t len,
                               uint8_t *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outl = 0, outl2 = 0;
    int rc = -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, output, &outl, input, (int)len) == 1 &&
        EVP_DecryptFinal_ex(ctx, output + outl, &outl2) == 1) {
        rc = 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
#else
/* ========== Standalone AES-256-CTR ========== */

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Multiply by 2 in GF(2^8) */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* AES-256 key expansion: 32-byte key → 240-byte round keys (15 rounds) */
static void aes256_expand_key(const uint8_t *key, uint8_t rk[240]) {
    int i;
    memcpy(rk, key, 32);
    for (i = 8; i < 60; i++) {
        uint8_t tmp[4];
        memcpy(tmp, rk + 4*(i-1), 4);
        if (i % 8 == 0) {
            uint8_t t = tmp[0];
            tmp[0] = AES_SBOX[tmp[1]] ^ AES_RCON[i/8];
            tmp[1] = AES_SBOX[tmp[2]];
            tmp[2] = AES_SBOX[tmp[3]];
            tmp[3] = AES_SBOX[t];
        } else if (i % 8 == 4) {
            tmp[0] = AES_SBOX[tmp[0]];
            tmp[1] = AES_SBOX[tmp[1]];
            tmp[2] = AES_SBOX[tmp[2]];
            tmp[3] = AES_SBOX[tmp[3]];
        }
        rk[4*i+0] = rk[4*(i-8)+0] ^ tmp[0];
        rk[4*i+1] = rk[4*(i-8)+1] ^ tmp[1];
        rk[4*i+2] = rk[4*(i-8)+2] ^ tmp[2];
        rk[4*i+3] = rk[4*(i-8)+3] ^ tmp[3];
    }
}

/* AES single block encrypt (for CTR mode) */
static void aes256_encrypt_block(const uint8_t rk[240], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    int i, r;
    memcpy(s, in, 16);

    /* AddRoundKey(0) */
    for (i = 0; i < 16; i++) s[i] ^= rk[i];

    for (r = 1; r < 14; r++) {
        uint8_t t[16];
        /* SubBytes */
        for (i = 0; i < 16; i++) t[i] = AES_SBOX[s[i]];
        /* ShiftRows */
        s[0]=t[0]; s[1]=t[5]; s[2]=t[10]; s[3]=t[15];
        s[4]=t[4]; s[5]=t[9]; s[6]=t[14]; s[7]=t[3];
        s[8]=t[8]; s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
        s[12]=t[12]; s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
        /* MixColumns */
        for (i = 0; i < 16; i += 4) {
            uint8_t a0=s[i], a1=s[i+1], a2=s[i+2], a3=s[i+3];
            s[i]   = xtime(a0)^xtime(a1)^a1^a2^a3;
            s[i+1] = a0^xtime(a1)^xtime(a2)^a2^a3;
            s[i+2] = a0^a1^xtime(a2)^xtime(a3)^a3;
            s[i+3] = xtime(a0)^a0^a1^a2^xtime(a3);
        }
        /* AddRoundKey */
        for (i = 0; i < 16; i++) s[i] ^= rk[r*16+i];
    }

    /* Final round (no MixColumns) */
    {
        uint8_t t[16];
        for (i = 0; i < 16; i++) t[i] = AES_SBOX[s[i]];
        s[0]=t[0]; s[1]=t[5]; s[2]=t[10]; s[3]=t[15];
        s[4]=t[4]; s[5]=t[9]; s[6]=t[14]; s[7]=t[3];
        s[8]=t[8]; s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
        s[12]=t[12]; s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
        for (i = 0; i < 16; i++) s[i] ^= rk[14*16+i];
    }

    memcpy(out, s, 16);
}

static int aes256_ctr_decrypt(const uint8_t *key, const uint8_t *iv,
                               const uint8_t *input, size_t len,
                               uint8_t *output) {
    uint8_t rk[240];
    uint8_t counter[16], keystream[16];
    size_t i, j;

    aes256_expand_key(key, rk);
    memcpy(counter, iv, 16);

    for (i = 0; i < len; i += 16) {
        aes256_encrypt_block(rk, counter, keystream);
        size_t block_len = (len - i < 16) ? (len - i) : 16;
        for (j = 0; j < block_len; j++)
            output[i + j] = input[i + j] ^ keystream[j];
        /* Increment counter (big-endian) */
        for (j = 15; j < 16; j--) {
            if (++counter[j] != 0) break;
        }
    }

    explicit_bzero(rk, sizeof(rk));
    explicit_bzero(keystream, sizeof(keystream));
    return 0;
}
#endif /* CHEZ_SSH_NO_OPENSSL */

/*
 * parse_openssh_key_private — Parse the decrypted private section.
 *
 * Extracts Ed25519 seed, public key, and comment from the inner
 * private section (after decryption if encrypted).
 * Returns 0 on success, -1 on error.
 */
static int parse_openssh_key_private(const uint8_t *priv_section, uint32_t priv_len,
                                      uint8_t *seed_out, uint8_t *pubkey_out,
                                      char *comment_out, size_t comment_max) {
    size_t ppos = 0;

    /* Check integers (must match — validates correct decryption) */
    uint32_t check1, check2;
    if (read_uint32(priv_section, priv_len, &ppos, &check1) < 0) return -1;
    if (read_uint32(priv_section, priv_len, &ppos, &check2) < 0) return -1;
    if (check1 != check2) return -1;  /* wrong passphrase */

    /* Key type — must be "ssh-ed25519" */
    const uint8_t *keytype;
    uint32_t keytype_len;
    if (read_string(priv_section, priv_len, &ppos, &keytype, &keytype_len) < 0) return -1;
    if (keytype_len != 11 || memcmp(keytype, "ssh-ed25519", 11) != 0) return -1;

    /* Public key (32 bytes) */
    const uint8_t *pk;
    uint32_t pk_len;
    if (read_string(priv_section, priv_len, &ppos, &pk, &pk_len) < 0) return -1;
    if (pk_len != 32) return -1;
    memcpy(pubkey_out, pk, 32);

    /* Private key (64 bytes: seed[32] || pubkey[32]) */
    const uint8_t *sk;
    uint32_t sk_len;
    if (read_string(priv_section, priv_len, &ppos, &sk, &sk_len) < 0) return -1;
    if (sk_len != 64) return -1;
    memcpy(seed_out, sk, 32);  /* first 32 bytes are the seed */

    /* Comment */
    const uint8_t *comment;
    uint32_t comment_len;
    if (read_string(priv_section, priv_len, &ppos, &comment, &comment_len) < 0) {
        comment_out[0] = '\0';
    } else {
        size_t clen = comment_len < comment_max - 1 ? comment_len : comment_max - 1;
        memcpy(comment_out, comment, clen);
        comment_out[clen] = '\0';
    }

    return 0;
}

/*
 * parse_openssh_key_header — Decode and parse the OpenSSH key header.
 *
 * Returns a malloc'd decoded buffer (caller must free), and fills in
 * cipher info, KDF params, and a pointer to the private section.
 * Returns NULL on error.
 */
static uint8_t *parse_openssh_key_header(const uint8_t *data, size_t len,
                                          char *cipher_out, size_t cipher_max,
                                          char *kdf_out, size_t kdf_max,
                                          const uint8_t **kdf_opts_out, uint32_t *kdf_opts_len,
                                          const uint8_t **priv_out, uint32_t *priv_len_out,
                                          int *declen_out) {
    const char *begin_marker = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const char *end_marker = "-----END OPENSSH PRIVATE KEY-----";
    (void)len;
    const char *begin = strstr((const char *)data, begin_marker);
    if (!begin) return NULL;
    begin += strlen(begin_marker);
    const char *end = strstr(begin, end_marker);
    if (!end) return NULL;

    size_t b64len = end - begin;
    size_t maxdec = (b64len * 3) / 4 + 4;
    uint8_t *dec = calloc(1, maxdec);
    if (!dec) return NULL;
    int declen = base64_decode((const uint8_t *)begin, b64len, dec, maxdec);
    if (declen < 0) { free(dec); return NULL; }
    *declen_out = declen;

    size_t pos = 0;

    /* Verify magic */
    if ((size_t)declen < OPENSSH_MAGIC_LEN ||
        memcmp(dec, OPENSSH_MAGIC, OPENSSH_MAGIC_LEN) != 0) {
        free(dec); return NULL;
    }
    pos = OPENSSH_MAGIC_LEN;

    /* Read cipher name */
    const uint8_t *sdata;
    uint32_t slen;
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return NULL; }
    {
        size_t clen = slen < cipher_max - 1 ? slen : cipher_max - 1;
        memcpy(cipher_out, sdata, clen);
        cipher_out[clen] = '\0';
    }

    /* Read KDF name */
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return NULL; }
    {
        size_t clen = slen < kdf_max - 1 ? slen : kdf_max - 1;
        memcpy(kdf_out, sdata, clen);
        kdf_out[clen] = '\0';
    }

    /* Read KDF options */
    if (read_string(dec, declen, &pos, kdf_opts_out, kdf_opts_len) < 0) { free(dec); return NULL; }

    /* Number of keys */
    uint32_t nkeys;
    if (read_uint32(dec, declen, &pos, &nkeys) < 0 || nkeys < 1) { free(dec); return NULL; }

    /* Skip public key blob */
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return NULL; }

    /* Private section */
    if (read_string(dec, declen, &pos, priv_out, priv_len_out) < 0) { free(dec); return NULL; }

    return dec;
}

/*
 * parse_openssh_key — Parse an unencrypted OpenSSH private key.
 * Backward compatible: only supports cipher "none".
 * Returns 0 on success, -1 on error.
 */
static int parse_openssh_key(const uint8_t *data, size_t len,
                             uint8_t *seed_out, uint8_t *pubkey_out,
                             char *comment_out, size_t comment_max) {
    char cipher[64], kdf[64];
    const uint8_t *kdf_opts, *priv_section;
    uint32_t kdf_opts_len, priv_len;
    int declen;

    uint8_t *dec = parse_openssh_key_header(data, len, cipher, sizeof(cipher),
                                             kdf, sizeof(kdf),
                                             &kdf_opts, &kdf_opts_len,
                                             &priv_section, &priv_len, &declen);
    if (!dec) return -1;

    /* Must be unencrypted */
    if (strcmp(cipher, "none") != 0) {
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }

    int rc = parse_openssh_key_private(priv_section, priv_len,
                                        seed_out, pubkey_out,
                                        comment_out, comment_max);
    explicit_bzero(dec, declen);
    free(dec);
    return rc;
}

/*
 * parse_openssh_key_encrypted — Parse an encrypted OpenSSH private key.
 *
 * Supports cipher "aes256-ctr" with KDF "bcrypt".
 * Returns 0 on success, -1 on error (wrong passphrase, unsupported cipher, etc.).
 */
static int parse_openssh_key_encrypted(const uint8_t *data, size_t len,
                                        const char *passphrase, size_t passlen,
                                        uint8_t *seed_out, uint8_t *pubkey_out,
                                        char *comment_out, size_t comment_max) {
    char cipher[64], kdf[64];
    const uint8_t *kdf_opts, *priv_section;
    uint32_t kdf_opts_len, priv_len;
    int declen;

    uint8_t *dec = parse_openssh_key_header(data, len, cipher, sizeof(cipher),
                                             kdf, sizeof(kdf),
                                             &kdf_opts, &kdf_opts_len,
                                             &priv_section, &priv_len, &declen);
    if (!dec) return -1;

    /* If not encrypted, just parse directly */
    if (strcmp(cipher, "none") == 0) {
        int rc = parse_openssh_key_private(priv_section, priv_len,
                                            seed_out, pubkey_out,
                                            comment_out, comment_max);
        explicit_bzero(dec, declen);
        free(dec);
        return rc;
    }

    /* Must be aes256-ctr with bcrypt KDF */
    if (strcmp(cipher, "aes256-ctr") != 0 || strcmp(kdf, "bcrypt") != 0) {
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }

    /* Parse KDF options: string(salt) || uint32(rounds) */
    const uint8_t *salt;
    uint32_t salt_len, rounds;
    size_t kpos = 0;
    if (read_string(kdf_opts, kdf_opts_len, &kpos, &salt, &salt_len) < 0) {
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }
    if (read_uint32(kdf_opts, kdf_opts_len, &kpos, &rounds) < 0) {
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }

    /* Derive key material: 32 bytes AES key + 16 bytes IV = 48 bytes */
    uint8_t derived[48];
    if (bcrypt_pbkdf(passphrase, passlen, salt, salt_len, rounds,
                     derived, sizeof(derived)) < 0) {
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }

    /* Decrypt the private section */
    uint8_t *decrypted = calloc(1, priv_len);
    if (!decrypted) {
        explicit_bzero(derived, sizeof(derived));
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }

    if (aes256_ctr_decrypt(derived, derived + 32, priv_section, priv_len, decrypted) < 0) {
        explicit_bzero(derived, sizeof(derived));
        explicit_bzero(decrypted, priv_len);
        free(decrypted);
        explicit_bzero(dec, declen);
        free(dec);
        return -1;
    }

    explicit_bzero(derived, sizeof(derived));

    /* Parse the decrypted private section */
    int rc = parse_openssh_key_private(decrypted, priv_len,
                                        seed_out, pubkey_out,
                                        comment_out, comment_max);

    explicit_bzero(decrypted, priv_len);
    free(decrypted);
    explicit_bzero(dec, declen);
    free(dec);
    return rc;
}

/* ========== Ed25519 Signing ========== */

#ifndef CHEZ_SSH_NO_OPENSSL
/*
 * ed25519_sign — Sign data with an Ed25519 seed (OpenSSL backend).
 * Returns 0 on success, -1 on error.
 */
static int ed25519_sign(const uint8_t *seed,
                        const uint8_t *data, size_t datalen,
                        uint8_t *sig_out) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, seed, ED25519_SEED);
    if (!pkey) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    size_t siglen = ED25519_SIG;
    int rc = -1;
    if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(mctx, sig_out, &siglen, data, datalen) == 1) {
        rc = 0;
    }

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/*
 * ed25519_derive_pubkey — Derive public key from seed (OpenSSL backend).
 * Returns 0 on success, -1 on error.
 */
static int ed25519_derive_pubkey(const uint8_t *seed, uint8_t *pubkey_out) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, seed, ED25519_SEED);
    if (!pkey) return -1;

    size_t publen = ED25519_PUB;
    int rc = EVP_PKEY_get_raw_public_key(pkey, pubkey_out, &publen) == 1 ? 0 : -1;
    EVP_PKEY_free(pkey);
    return rc;
}
#else
/* Standalone backend — no OpenSSL dependency */
static int ed25519_sign(const uint8_t *seed,
                        const uint8_t *data, size_t datalen,
                        uint8_t *sig_out) {
    return ed25519_sign_standalone(seed, data, datalen, sig_out);
}
static int ed25519_derive_pubkey(const uint8_t *seed, uint8_t *pubkey_out) {
    return ed25519_derive_pubkey_standalone(seed, pubkey_out);
}
#endif

/* ========== Key Management ========== */

/*
 * Build the SSH public key blob for an Ed25519 key:
 *   string "ssh-ed25519" || string pubkey(32)
 * Total: 4+11+4+32 = 51 bytes
 */
#define ED25519_BLOB_SIZE 51

static void build_pubkey_blob(const uint8_t *pubkey, uint8_t *blob) {
    size_t pos = 0;
    write_string(blob, &pos, (const uint8_t *)"ssh-ed25519", 11);
    write_string(blob, &pos, pubkey, ED25519_PUB);
}

int chez_ssh_agent_load_openssh_key(const uint8_t *data, int len) {
    if (_key_count >= MAX_KEYS) return -1;

    harden_keys();

    int idx = _key_count;
    ssh_key_t *k = &_keys[idx];
    memset(k, 0, sizeof(*k));

    if (parse_openssh_key(data, len, k->seed, k->pubkey,
                          k->comment, MAX_COMMENT) < 0) {
        explicit_bzero(k, sizeof(*k));
        return -1;
    }

    k->active = 1;
    _key_count++;
    return idx;
}

/*
 * chez_ssh_key_is_encrypted — Check if an OpenSSH key file is encrypted.
 * Returns: 1 = encrypted, 0 = unencrypted, -1 = not a valid OpenSSH key.
 */
int chez_ssh_key_is_encrypted(const uint8_t *data, int len) {
    char cipher[64], kdf[64];
    const uint8_t *kdf_opts, *priv_section;
    uint32_t kdf_opts_len, priv_len;
    int declen;

    uint8_t *dec = parse_openssh_key_header(data, len, cipher, sizeof(cipher),
                                             kdf, sizeof(kdf),
                                             &kdf_opts, &kdf_opts_len,
                                             &priv_section, &priv_len, &declen);
    if (!dec) return -1;
    int encrypted = strcmp(cipher, "none") != 0 ? 1 : 0;
    free(dec);
    return encrypted;
}

/*
 * chez_ssh_agent_load_openssh_key_with_pass — Load an encrypted OpenSSH key
 * with an explicit passphrase.
 *
 * Also works for unencrypted keys (passphrase ignored).
 * Returns key index on success, -1 on error.
 */
int chez_ssh_agent_load_openssh_key_with_pass(const uint8_t *data, int len,
                                               const char *pass, int passlen) {
    if (_key_count >= MAX_KEYS) return -1;

    harden_keys();

    int idx = _key_count;
    ssh_key_t *k = &_keys[idx];
    memset(k, 0, sizeof(*k));

    if (parse_openssh_key_encrypted(data, len, pass, passlen,
                                     k->seed, k->pubkey,
                                     k->comment, MAX_COMMENT) < 0) {
        explicit_bzero(k, sizeof(*k));
        return -1;
    }

    k->active = 1;
    _key_count++;
    return idx;
}

/*
 * chez_ssh_agent_load_key_prompted — Load an OpenSSH key, prompting for
 * passphrase on /dev/tty if encrypted.
 *
 * The passphrase never enters Scheme memory — it stays on the C stack
 * and is zeroed immediately after use.
 *
 * Returns key index on success, -1 on error.
 */
int chez_ssh_agent_load_key_prompted(const uint8_t *data, int len,
                                      const char *prompt) {
    /* First check if the key is encrypted */
    int encrypted = chez_ssh_key_is_encrypted(data, len);
    if (encrypted < 0) return -1;

    if (!encrypted) {
        /* Unencrypted — load directly */
        return chez_ssh_agent_load_openssh_key(data, len);
    }

    /* Read passphrase from /dev/tty */
    int tty_fd = open("/dev/tty", O_RDWR);
    if (tty_fd < 0) return -1;

    /* Disable echo */
    struct termios old_term, new_term;
    if (tcgetattr(tty_fd, &old_term) < 0) {
        close(tty_fd);
        return -1;
    }
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO | ECHONL);
    tcsetattr(tty_fd, TCSANOW, &new_term);

    /* Write prompt */
    if (prompt && prompt[0]) {
        ssize_t r;
        size_t plen = strlen(prompt);
        do { r = write(tty_fd, prompt, plen); } while (r < 0 && errno == EINTR);
    }

    /* Read passphrase (up to 1024 bytes) */
    char passbuf[1024];
    int passlen = 0;
    for (;;) {
        ssize_t r = read(tty_fd, passbuf + passlen, 1);
        if (r <= 0) break;
        if (passbuf[passlen] == '\n' || passbuf[passlen] == '\r') break;
        passlen++;
        if (passlen >= (int)sizeof(passbuf) - 1) break;
    }
    passbuf[passlen] = '\0';

    /* Restore echo, write newline */
    tcsetattr(tty_fd, TCSANOW, &old_term);
    { ssize_t r; do { r = write(tty_fd, "\n", 1); } while (r < 0 && errno == EINTR); }
    close(tty_fd);

    /* Load the key with the passphrase */
    int idx = chez_ssh_agent_load_openssh_key_with_pass(data, len, passbuf, passlen);

    /* Zero the passphrase immediately */
    explicit_bzero(passbuf, sizeof(passbuf));

    return idx;
}

int chez_ssh_agent_load_ed25519(const uint8_t *seed, const char *comment) {
    if (_key_count >= MAX_KEYS) return -1;

    harden_keys();

    int idx = _key_count;
    ssh_key_t *k = &_keys[idx];
    memset(k, 0, sizeof(*k));

    memcpy(k->seed, seed, ED25519_SEED);
    if (ed25519_derive_pubkey(seed, k->pubkey) < 0) {
        explicit_bzero(k, sizeof(*k));
        return -1;
    }

    if (comment) {
        strncpy(k->comment, comment, MAX_COMMENT - 1);
        k->comment[MAX_COMMENT - 1] = '\0';
    }

    k->active = 1;
    _key_count++;
    return idx;
}

int chez_ssh_agent_key_count(void) {
    return _key_count;
}

int chez_ssh_agent_get_pubkey_blob(int index, uint8_t *out, int max_out) {
    if (index < 0 || index >= _key_count || !_keys[index].active) return -1;
    if (max_out < ED25519_BLOB_SIZE) return -1;
    build_pubkey_blob(_keys[index].pubkey, out);
    return ED25519_BLOB_SIZE;
}

/* Copy comment into caller's buffer. Returns length or -1. */
int chez_ssh_agent_get_comment(int index, char *out, int max_out) {
    if (index < 0 || index >= _key_count || !_keys[index].active) return -1;
    int len = strlen(_keys[index].comment);
    if (len >= max_out) len = max_out - 1;
    memcpy(out, _keys[index].comment, len);
    out[len] = '\0';
    return len;
}

void chez_ssh_agent_remove_key(int index) {
    if (index < 0 || index >= _key_count) return;
    explicit_bzero(&_keys[index], sizeof(ssh_key_t));
    /* Compact the array */
    for (int i = index; i < _key_count - 1; i++) {
        _keys[i] = _keys[i + 1];
    }
    explicit_bzero(&_keys[_key_count - 1], sizeof(ssh_key_t));
    _key_count--;
}

void chez_ssh_agent_remove_all(void) {
    explicit_bzero(_keys, sizeof(_keys));
    _key_count = 0;
}

/* ========== Agent Protocol ========== */

/* Find key by matching public key blob */
static int find_key_by_blob(const uint8_t *blob, uint32_t bloblen) {
    if (bloblen != ED25519_BLOB_SIZE) return -1;

    uint8_t candidate[ED25519_BLOB_SIZE];
    for (int i = 0; i < _key_count; i++) {
        if (!_keys[i].active) continue;
        build_pubkey_blob(_keys[i].pubkey, candidate);
        if (memcmp(candidate, blob, ED25519_BLOB_SIZE) == 0)
            return i;
    }
    return -1;
}

/*
 * handle_identities — Build SSH_AGENT_IDENTITIES_ANSWER.
 * Format: byte(12) || uint32(nkeys) || for each: string(blob) || string(comment)
 */
static int handle_identities(uint8_t *resp, size_t maxresp) {
    size_t pos = 0;

    /* Leave room for outer length (4 bytes), filled in at end */
    pos = 4;

    /* Message type */
    if (pos >= maxresp) return -1;
    resp[pos++] = SSH_AGENT_IDENTITIES_ANSWER;

    /* Count active keys */
    int nactive = 0;
    for (int i = 0; i < _key_count; i++)
        if (_keys[i].active) nactive++;

    write_uint32(resp, &pos, nactive);

    for (int i = 0; i < _key_count; i++) {
        if (!_keys[i].active) continue;
        /* Public key blob */
        uint8_t blob[ED25519_BLOB_SIZE];
        build_pubkey_blob(_keys[i].pubkey, blob);
        if (pos + 4 + ED25519_BLOB_SIZE + 4 + MAX_COMMENT > maxresp) return -1;
        write_string(resp, &pos, blob, ED25519_BLOB_SIZE);
        /* Comment */
        uint32_t clen = strlen(_keys[i].comment);
        write_string(resp, &pos, (const uint8_t *)_keys[i].comment, clen);
    }

    /* Fill in outer length (message length, not including the 4-byte length itself) */
    size_t msg_len = pos - 4;
    size_t lpos = 0;
    write_uint32(resp, &lpos, msg_len);

    return (int)pos;
}

/*
 * handle_sign — Process SSH_AGENTC_SIGN_REQUEST, build SSH_AGENT_SIGN_RESPONSE.
 */
static int handle_sign(const uint8_t *payload, size_t paylen,
                       uint8_t *resp, size_t maxresp) {
    (void)maxresp;
    size_t ppos = 0;

    /* Read key blob */
    const uint8_t *key_blob;
    uint32_t key_blob_len;
    if (read_string(payload, paylen, &ppos, &key_blob, &key_blob_len) < 0)
        return -1;

    /* Read data to sign */
    const uint8_t *data;
    uint32_t datalen;
    if (read_string(payload, paylen, &ppos, &data, &datalen) < 0)
        return -1;

    /* Read flags (ignored for Ed25519) */
    uint32_t flags = 0;
    read_uint32(payload, paylen, &ppos, &flags);

    /* Find matching key */
    int kidx = find_key_by_blob(key_blob, key_blob_len);
    if (kidx < 0) return -1;

    /* Sign */
    uint8_t signature[ED25519_SIG];
    if (ed25519_sign(_keys[kidx].seed, data, datalen, signature) < 0)
        return -1;

    /* Build response:
     * uint32(outer_len) || byte(14) || string(sig_blob)
     * sig_blob = string("ssh-ed25519") || string(signature_64)
     * sig_blob size = 4+11+4+64 = 83 bytes
     */
    #define SIG_BLOB_SIZE 83

    size_t pos = 4; /* skip outer length */

    resp[pos++] = SSH_AGENT_SIGN_RESPONSE;

    /* Build signature blob in-place */
    /* First, write outer string length for sig_blob */
    write_uint32(resp, &pos, SIG_BLOB_SIZE);
    /* sig_blob contents */
    write_string(resp, &pos, (const uint8_t *)"ssh-ed25519", 11);
    write_string(resp, &pos, signature, ED25519_SIG);

    /* Fill in outer length */
    size_t msg_len = pos - 4;
    size_t lpos = 0;
    write_uint32(resp, &lpos, msg_len);

    return (int)pos;
}

/* Send a simple failure response */
static int build_failure(uint8_t *resp) {
    size_t pos = 0;
    write_uint32(resp, &pos, 1);  /* length = 1 byte */
    resp[pos++] = SSH_AGENT_FAILURE;
    return (int)pos;
}

/* ========== Socket I/O ========== */

/* Read exactly n bytes from fd. Returns 0 on success, -1 on error/EOF. */
static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        done += r;
    }
    return 0;
}

/* Write exactly n bytes to fd. Returns 0 on success, -1 on error. */
static int write_exact(int fd, const uint8_t *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, buf + done, n - done);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        done += w;
    }
    return 0;
}

/* Handle a single client connection (may have multiple messages) */
static void handle_client(int client_fd) {
    uint8_t lenbuf[4];
    uint8_t *msg = NULL;
    uint8_t *resp = NULL;

    /* Allocate response buffer (generous size) */
    resp = malloc(MAX_MSG);
    if (!resp) goto done;

    while (1) {
        /* Read 4-byte message length */
        if (read_exact(client_fd, lenbuf, 4) < 0) break;

        uint32_t msglen = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) |
                          ((uint32_t)lenbuf[2] << 8) | lenbuf[3];

        if (msglen == 0 || msglen > MAX_MSG) break;

        /* Read message body */
        msg = malloc(msglen);
        if (!msg) break;
        if (read_exact(client_fd, msg, msglen) < 0) { free(msg); msg = NULL; break; }

        uint8_t msg_type = msg[0];
        int resp_len;

        switch (msg_type) {
        case SSH_AGENTC_REQUEST_IDENTITIES:
            resp_len = handle_identities(resp, MAX_MSG);
            break;

        case SSH_AGENTC_SIGN_REQUEST:
            resp_len = handle_sign(msg + 1, msglen - 1, resp, MAX_MSG);
            break;

        case SSH_AGENTC_REMOVE_ALL_IDENTITIES:
            chez_ssh_agent_remove_all();
            resp_len = 5; /* length(4) + SUCCESS(1) */
            { size_t p = 0; write_uint32(resp, &p, 1); resp[4] = SSH_AGENT_SUCCESS; }
            break;

        default:
            resp_len = -1;
            break;
        }

        if (resp_len < 0) {
            resp_len = build_failure(resp);
        }

        write_exact(client_fd, resp, resp_len);

        free(msg);
        msg = NULL;
    }

done:
    if (msg) free(msg);
    if (resp) free(resp);
    close(client_fd);
}

/* ========== Socket Server ========== */

static void *agent_thread_fn(void *arg) {
    (void)arg;

    /* Block signals in this thread — let main thread handle them */
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);

    while (_agent_running) {
        struct pollfd pfds[2];
        pfds[0].fd = _agent_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = _agent_wakeup_pipe[0];
        pfds[1].events = POLLIN;

        int nready = poll(pfds, 2, -1);
        if (nready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Wakeup pipe signalled — time to stop */
        if (pfds[1].revents & POLLIN) break;

        /* New client connection */
        if (pfds[0].revents & POLLIN) {
            int client = accept(_agent_fd, NULL, NULL);
            if (client < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                break;
            }
            handle_client(client);
        }
    }

    return NULL;
}

int chez_ssh_agent_start(const char *socket_dir) {
    if (_agent_running) return 0;  /* already running */

    /* Determine socket directory */
    const char *dir = socket_dir;
    if (!dir || dir[0] == '\0') {
        dir = getenv("XDG_RUNTIME_DIR");
        if (!dir) dir = "/tmp";
    }

    /* Create agent-specific subdirectory: <dir>/jsh-agent-<pid>/ */
    pid_t pid = getpid();
    snprintf(_agent_dir, sizeof(_agent_dir), "%s/jsh-agent-%d", dir, pid);
    if (mkdir(_agent_dir, 0700) < 0 && errno != EEXIST) return -1;

    /* Socket path: <dir>/jsh-agent-<pid>/agent.<pid> */
    snprintf(_agent_path, sizeof(_agent_path), "%s/agent.%d", _agent_dir, pid);

    /* Remove stale socket */
    unlink(_agent_path);

    /* Create Unix domain socket */
    _agent_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_agent_fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, _agent_path, sizeof(addr.sun_path) - 1);

    if (bind(_agent_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(_agent_fd); _agent_fd = -1; return -1;
    }

    /* Owner-only access */
    chmod(_agent_path, 0600);

    if (listen(_agent_fd, 8) < 0) {
        close(_agent_fd); _agent_fd = -1;
        unlink(_agent_path);
        return -1;
    }

    /* Create wakeup pipe for clean shutdown */
    if (pipe(_agent_wakeup_pipe) < 0) {
        close(_agent_fd); _agent_fd = -1;
        unlink(_agent_path);
        return -1;
    }

    /* Start accept thread */
    _agent_running = 1;
    if (pthread_create(&_agent_thread, NULL, agent_thread_fn, NULL) != 0) {
        _agent_running = 0;
        close(_agent_fd); _agent_fd = -1;
        close(_agent_wakeup_pipe[0]); close(_agent_wakeup_pipe[1]);
        _agent_wakeup_pipe[0] = _agent_wakeup_pipe[1] = -1;
        unlink(_agent_path);
        return -1;
    }

    return 0;
}

const char *chez_ssh_agent_get_socket_path(void) {
    if (!_agent_running) return NULL;
    return _agent_path;
}

int chez_ssh_agent_is_running(void) {
    return _agent_running;
}

void chez_ssh_agent_stop(void) {
    if (!_agent_running) return;

    _agent_running = 0;

    /* Signal the accept thread to wake up */
    if (_agent_wakeup_pipe[1] >= 0) {
        uint8_t byte = 1;
        ssize_t r;
        do { r = write(_agent_wakeup_pipe[1], &byte, 1); } while (r < 0 && errno == EINTR);
    }

    pthread_join(_agent_thread, NULL);

    if (_agent_fd >= 0) { close(_agent_fd); _agent_fd = -1; }
    if (_agent_wakeup_pipe[0] >= 0) { close(_agent_wakeup_pipe[0]); _agent_wakeup_pipe[0] = -1; }
    if (_agent_wakeup_pipe[1] >= 0) { close(_agent_wakeup_pipe[1]); _agent_wakeup_pipe[1] = -1; }

    /* Clean up socket file and directory */
    if (_agent_path[0]) { unlink(_agent_path); _agent_path[0] = '\0'; }
    if (_agent_dir[0])  { rmdir(_agent_dir);   _agent_dir[0] = '\0'; }

    /* Zero all keys */
    chez_ssh_agent_remove_all();
}
