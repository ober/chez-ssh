/*
 * chez_ssh_crypto.c — Crypto and networking primitives for SSH client
 *
 * All crypto via OpenSSL 3.x. Protocol logic stays in Scheme;
 * only raw primitives live here.
 *
 * Link with: -lcrypto
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "chez_ssh_crypto.h"

/* ========== Random ========== */

int chez_ssh_random_bytes(uint8_t *out, int len) {
    if (!out || len <= 0) return -1;
    return RAND_bytes(out, len) == 1 ? 0 : -1;
}

/* ========== Hashing ========== */

int chez_ssh_sha256(const uint8_t *data, int len, uint8_t *out32) {
    if (!data || !out32 || len < 0) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    unsigned int mdlen = 32;
    int rc = -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, len) == 1 &&
        EVP_DigestFinal_ex(ctx, out32, &mdlen) == 1) {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

int chez_ssh_sha512(const uint8_t *data, int len, uint8_t *out64) {
    if (!data || !out64 || len < 0) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    unsigned int mdlen = 64;
    int rc = -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, len) == 1 &&
        EVP_DigestFinal_ex(ctx, out64, &mdlen) == 1) {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

/* ========== HMAC ========== */

int chez_ssh_hmac_sha256(const uint8_t *key, int keylen,
                         const uint8_t *data, int datalen,
                         uint8_t *out32) {
    if (!key || !data || !out32 || keylen <= 0 || datalen < 0) return -1;
    unsigned int mdlen = 32;
    uint8_t *result = HMAC(EVP_sha256(), key, keylen, data, datalen, out32, &mdlen);
    return result ? 0 : -1;
}

int chez_ssh_hmac_sha512(const uint8_t *key, int keylen,
                         const uint8_t *data, int datalen,
                         uint8_t *out64) {
    if (!key || !data || !out64 || keylen <= 0 || datalen < 0) return -1;
    unsigned int mdlen = 64;
    uint8_t *result = HMAC(EVP_sha512(), key, keylen, data, datalen, out64, &mdlen);
    return result ? 0 : -1;
}

/* ========== Curve25519 ECDH ========== */

int chez_ssh_curve25519_keygen(uint8_t *privkey32, uint8_t *pubkey32) {
    if (!privkey32 || !pubkey32) return -1;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return -1;

    int rc = -1;
    if (EVP_PKEY_keygen_init(pctx) == 1 &&
        EVP_PKEY_keygen(pctx, &pkey) == 1) {
        size_t privlen = 32, publen = 32;
        if (EVP_PKEY_get_raw_private_key(pkey, privkey32, &privlen) == 1 &&
            EVP_PKEY_get_raw_public_key(pkey, pubkey32, &publen) == 1) {
            rc = 0;
        }
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int chez_ssh_curve25519_shared_secret(const uint8_t *priv32,
                                      const uint8_t *peer_pub32,
                                      uint8_t *secret_out,
                                      int *secret_len) {
    if (!priv32 || !peer_pub32 || !secret_out || !secret_len) return -1;

    EVP_PKEY *our_key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, NULL, priv32, 32);
    if (!our_key) return -1;

    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, peer_pub32, 32);
    if (!peer_key) { EVP_PKEY_free(our_key); return -1; }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_key, NULL);
    int rc = -1;
    if (ctx) {
        size_t slen = 32;
        if (EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, peer_key) == 1 &&
            EVP_PKEY_derive(ctx, secret_out, &slen) == 1) {
            *secret_len = (int)slen;
            rc = 0;
        }
        EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY_free(our_key);
    EVP_PKEY_free(peer_key);
    return rc;
}

/* ========== ChaCha20-Poly1305 (SSH variant) ========== */
/*
 * SSH ChaCha20-Poly1305 (OpenSSH variant, NOT RFC 8439 AEAD)
 *
 * key64 = K2(32 bytes, main/payload key) || K1(32 bytes, length key)
 * Nonce = seqno as big-endian 64-bit, zero-padded to 8 bytes
 *
 * OpenSSH uses DJB ChaCha20 with raw Poly1305 (no RFC 8439 padding/length).
 * The nonce layout is compatible with IETF ChaCha20 when using:
 *   OpenSSL IV = counter(4 LE) || 0x00000000 || seqno_be64
 *
 * Encryption:
 *   1. Encrypt 4-byte packet length with K1/ChaCha20, counter=0
 *   2. Generate Poly1305 key: first 32 bytes of ChaCha20(K2, counter=0)
 *   3. Encrypt payload with K2/ChaCha20, counter=1
 *   4. Poly1305 MAC over (enc_length || enc_payload) using raw poly1305 key
 *
 * Input  plaintext: length(4) || padding_len(1) || payload || padding
 * Output:           enc_length(4) || enc_payload(len-4) || tag(16)
 */

/* Build OpenSSL ChaCha20 16-byte IV: counter(4 LE) || nonce(12)
 * nonce(12) = 0x00000000 || seqno(8 BE) */
static void build_chacha_iv(uint64_t seqno, uint32_t counter, uint8_t *iv16) {
    /* counter as 4-byte little-endian */
    iv16[0] = counter & 0xFF;
    iv16[1] = (counter >> 8) & 0xFF;
    iv16[2] = (counter >> 16) & 0xFF;
    iv16[3] = (counter >> 24) & 0xFF;
    /* 4 zero bytes */
    iv16[4] = 0; iv16[5] = 0; iv16[6] = 0; iv16[7] = 0;
    /* seqno as 8-byte big-endian */
    iv16[8]  = (seqno >> 56) & 0xFF;
    iv16[9]  = (seqno >> 48) & 0xFF;
    iv16[10] = (seqno >> 40) & 0xFF;
    iv16[11] = (seqno >> 32) & 0xFF;
    iv16[12] = (seqno >> 24) & 0xFF;
    iv16[13] = (seqno >> 16) & 0xFF;
    iv16[14] = (seqno >> 8)  & 0xFF;
    iv16[15] = seqno & 0xFF;
}

/* Run ChaCha20 stream cipher (encrypt = decrypt for XOR cipher) */
static int chacha20_xor(const uint8_t *key32, uint64_t seqno, uint32_t counter,
                        const uint8_t *in, int inlen, uint8_t *out) {
    uint8_t iv[16];
    build_chacha_iv(seqno, counter, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int tmplen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key32, iv) != 1 ||
        EVP_EncryptUpdate(ctx, out, &tmplen, in, inlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* Compute raw Poly1305 MAC (no RFC 8439 padding/lengths) */
static int poly1305_mac(const uint8_t *key32, const uint8_t *data, int datalen,
                        uint8_t *tag16) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (!mac) return -1;

    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!mctx) return -1;

    size_t taglen = 16;
    if (EVP_MAC_init(mctx, key32, 32, NULL) != 1 ||
        EVP_MAC_update(mctx, data, datalen) != 1 ||
        EVP_MAC_final(mctx, tag16, &taglen, 16) != 1) {
        EVP_MAC_CTX_free(mctx);
        return -1;
    }
    EVP_MAC_CTX_free(mctx);
    return 0;
}

int chez_ssh_chacha20_poly1305_encrypt(const uint8_t *key64, uint64_t seqno,
    const uint8_t *plaintext, int len,
    uint8_t *out, uint8_t *out_len) {
    if (!key64 || !plaintext || !out || !out_len || len < 4) return -1;

    const uint8_t *K2 = key64;        /* main key (payload) */
    const uint8_t *K1 = key64 + 32;   /* length key */
    int plen = len - 4;               /* payload bytes after 4-byte length */

    /* Step 1: Encrypt the 4-byte length with K1, counter=0 */
    if (chacha20_xor(K1, seqno, 0, plaintext, 4, out) != 0)
        return -1;

    /* Step 2: Generate Poly1305 key from K2, counter=0 */
    uint8_t poly_key_input[64];
    uint8_t poly_key[64];
    memset(poly_key_input, 0, 64);
    if (chacha20_xor(K2, seqno, 0, poly_key_input, 64, poly_key) != 0)
        return -1;

    /* Step 3: Encrypt payload with K2, counter=1 */
    if (chacha20_xor(K2, seqno, 1, plaintext + 4, plen, out + 4) != 0)
        return -1;

    /* Step 4: Poly1305 MAC over enc_length(4) || enc_payload(plen) */
    uint8_t tag[16];
    if (poly1305_mac(poly_key, out, 4 + plen, tag) != 0)
        return -1;
    memcpy(out + 4 + plen, tag, 16);

    /* Clear poly key */
    OPENSSL_cleanse(poly_key, sizeof(poly_key));

    /* Write out_len as big-endian uint32 */
    {
        uint32_t total = 4 + plen + 16;
        out_len[0] = (total >> 24) & 0xFF;
        out_len[1] = (total >> 16) & 0xFF;
        out_len[2] = (total >> 8)  & 0xFF;
        out_len[3] = total & 0xFF;
    }
    return 0;
}

int chez_ssh_chacha20_poly1305_decrypt_length(const uint8_t *key64,
    uint64_t seqno,
    const uint8_t *enc4,
    uint8_t *length_out) {
    if (!key64 || !enc4 || !length_out) return -1;

    const uint8_t *K1 = key64 + 32;
    /* Decrypt length with K1, counter=0 */
    if (chacha20_xor(K1, seqno, 0, enc4, 4, length_out) != 0)
        return -1;
    return 0;
}

int chez_ssh_chacha20_poly1305_decrypt(const uint8_t *key64, uint64_t seqno,
    const uint8_t *ciphertext, int len,
    uint8_t *out, uint8_t *out_len) {
    /* ciphertext layout: enc_length(4) || enc_payload(len-4-16) || tag(16) */
    if (!key64 || !ciphertext || !out || !out_len || len < 20) return -1;

    const uint8_t *K2 = key64;
    const uint8_t *enc_length = ciphertext;
    int payload_len = len - 4 - 16;
    const uint8_t *enc_payload = ciphertext + 4;
    const uint8_t *tag = ciphertext + 4 + payload_len;

    /* Step 1: Generate Poly1305 key from K2, counter=0 */
    uint8_t poly_key_input[64];
    uint8_t poly_key[64];
    memset(poly_key_input, 0, 64);
    if (chacha20_xor(K2, seqno, 0, poly_key_input, 64, poly_key) != 0)
        return -1;

    /* Step 2: Verify Poly1305 MAC over enc_length(4) || enc_payload */
    uint8_t computed_tag[16];
    if (poly1305_mac(poly_key, ciphertext, 4 + payload_len, computed_tag) != 0) {
        OPENSSL_cleanse(poly_key, sizeof(poly_key));
        return -1;
    }
    OPENSSL_cleanse(poly_key, sizeof(poly_key));

    if (CRYPTO_memcmp(computed_tag, tag, 16) != 0)
        return -2;  /* MAC verification failed */

    /* Step 3: Decrypt length with K1, counter=0 */
    uint8_t dec_len_bytes[4];
    if (chez_ssh_chacha20_poly1305_decrypt_length(key64, seqno, enc_length, dec_len_bytes) != 0)
        return -1;

    out[0] = dec_len_bytes[0];
    out[1] = dec_len_bytes[1];
    out[2] = dec_len_bytes[2];
    out[3] = dec_len_bytes[3];

    /* Step 4: Decrypt payload with K2, counter=1 */
    if (chacha20_xor(K2, seqno, 1, enc_payload, payload_len, out + 4) != 0)
        return -1;

    /* Write out_len as big-endian uint32 */
    {
        uint32_t total = 4 + payload_len;
        out_len[0] = (total >> 24) & 0xFF;
        out_len[1] = (total >> 16) & 0xFF;
        out_len[2] = (total >> 8)  & 0xFF;
        out_len[3] = total & 0xFF;
    }
    return 0;
}

/* ========== AES-256-CTR ========== */
/*
 * We store an EVP_CIPHER_CTX pointer inside the caller's buffer.
 * The buffer must be at least sizeof(void*) bytes.
 */

int chez_ssh_aes256_ctr_init(const uint8_t *key32, const uint8_t *iv16,
                             uint8_t *ctx_buf, int ctx_size) {
    if (!key32 || !iv16 || !ctx_buf || ctx_size < (int)sizeof(void*)) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key32, iv16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(ctx_buf, &ctx, sizeof(void*));
    return 0;
}

int chez_ssh_aes256_ctr_process(uint8_t *ctx_buf, const uint8_t *in, int len,
                                uint8_t *out) {
    if (!ctx_buf || !in || !out || len <= 0) return -1;
    EVP_CIPHER_CTX *ctx;
    memcpy(&ctx, ctx_buf, sizeof(void*));
    if (!ctx) return -1;

    int tmplen = 0;
    if (EVP_EncryptUpdate(ctx, out, &tmplen, in, len) != 1) return -1;
    return tmplen;
}

int chez_ssh_aes256_ctr_free(uint8_t *ctx_buf) {
    if (!ctx_buf) return -1;
    EVP_CIPHER_CTX *ctx;
    memcpy(&ctx, ctx_buf, sizeof(void*));
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        memset(ctx_buf, 0, sizeof(void*));
    }
    return 0;
}

/* ========== Ed25519 ========== */

int chez_ssh_ed25519_verify(const uint8_t *pubkey32,
                            const uint8_t *data, int datalen,
                            const uint8_t *sig64) {
    if (!pubkey32 || !data || !sig64 || datalen < 0) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, NULL, pubkey32, 32);
    if (!pkey) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    int rc = -1;
    if (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(mctx, sig64, 64, data, datalen) == 1) {
        rc = 0;
    }

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int chez_ssh_ed25519_sign(const uint8_t *seed32,
                          const uint8_t *data, int datalen,
                          uint8_t *sig64) {
    if (!seed32 || !data || !sig64 || datalen < 0) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, seed32, 32);
    if (!pkey) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    size_t siglen = 64;
    int rc = -1;
    if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(mctx, sig64, &siglen, data, datalen) == 1) {
        rc = 0;
    }

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ========== Ed25519 Derive Public Key ========== */

int chez_ssh_ed25519_derive_pubkey(const uint8_t *seed32, uint8_t *pubkey32) {
    if (!seed32 || !pubkey32) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, seed32, 32);
    if (!pkey) return -1;

    size_t publen = 32;
    int rc = EVP_PKEY_get_raw_public_key(pkey, pubkey32, &publen) == 1 ? 0 : -1;
    EVP_PKEY_free(pkey);
    return rc;
}

/* ========== TCP Networking ========== */

int chez_ssh_tcp_connect(const char *host, int port) {
    if (!host || port <= 0 || port > 65535) return -1;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai_rc = getaddrinfo(host, port_str, &hints, &res);
    if (gai_rc != 0) return -1;

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int chez_ssh_tcp_read(int fd, uint8_t *buf, int maxlen) {
    if (fd < 0 || !buf || maxlen <= 0) return -1;
    ssize_t n;
    do {
        n = read(fd, buf, maxlen);
    } while (n < 0 && errno == EINTR);
    return (int)n;
}

int chez_ssh_tcp_write(int fd, const uint8_t *buf, int len) {
    if (fd < 0 || !buf || len <= 0) return -1;
    int total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (int)n;
    }
    return total;
}

int chez_ssh_tcp_close(int fd) {
    if (fd < 0) return -1;
    return close(fd) == 0 ? 0 : -1;
}

int chez_ssh_tcp_listen(const char *bind_addr, int port) {
    if (port <= 0 || port > 65535) return -1;

    const char *addr = (bind_addr && *bind_addr) ? bind_addr : "127.0.0.1";
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(addr, port_str, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0 ||
        listen(fd, 16) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

int chez_ssh_tcp_accept(int listen_fd) {
    if (listen_fd < 0) return -1;
    int fd;
    do {
        fd = accept(listen_fd, NULL, NULL);
    } while (fd < 0 && errno == EINTR);
    return fd;
}

int chez_ssh_tcp_set_nodelay(int fd, int enable) {
    if (fd < 0) return -1;
    int flag = enable ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == 0 ? 0 : -1;
}
