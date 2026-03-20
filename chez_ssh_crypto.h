/*
 * chez_ssh_crypto.h — Crypto and networking primitives for SSH client
 *
 * OpenSSL-based: ECDH (Curve25519), ChaCha20-Poly1305, AES-256-CTR,
 * HMAC-SHA2, SHA-256/512, Ed25519 verify/sign, TCP sockets.
 */

#ifndef CHEZ_SSH_CRYPTO_H
#define CHEZ_SSH_CRYPTO_H

#include <stdint.h>

/* ========== Random ========== */
int chez_ssh_random_bytes(uint8_t *out, int len);

/* ========== Hashing ========== */
int chez_ssh_sha256(const uint8_t *data, int len, uint8_t *out32);
int chez_ssh_sha512(const uint8_t *data, int len, uint8_t *out64);

/* ========== HMAC ========== */
int chez_ssh_hmac_sha256(const uint8_t *key, int keylen,
                         const uint8_t *data, int datalen,
                         uint8_t *out32);
int chez_ssh_hmac_sha512(const uint8_t *key, int keylen,
                         const uint8_t *data, int datalen,
                         uint8_t *out64);

/* ========== Curve25519 ECDH ========== */
int chez_ssh_curve25519_keygen(uint8_t *privkey32, uint8_t *pubkey32);
int chez_ssh_curve25519_shared_secret(const uint8_t *priv32,
                                      const uint8_t *peer_pub32,
                                      uint8_t *secret_out,
                                      int *secret_len);

/* ========== ChaCha20-Poly1305 (SSH variant) ========== */
int chez_ssh_chacha20_poly1305_encrypt(const uint8_t *key64, uint64_t seqno,
    const uint8_t *plaintext, int len,
    uint8_t *out, uint8_t *out_len);
int chez_ssh_chacha20_poly1305_decrypt(const uint8_t *key64, uint64_t seqno,
    const uint8_t *ciphertext, int len,
    uint8_t *out, uint8_t *out_len);
int chez_ssh_chacha20_poly1305_decrypt_length(const uint8_t *key64,
    uint64_t seqno,
    const uint8_t *enc4,
    uint8_t *length_out);

/* ========== AES-256-CTR ========== */
#define CHEZ_SSH_AES_CTX_SIZE 512  /* enough for EVP_CIPHER_CTX */
int chez_ssh_aes256_ctr_init(const uint8_t *key32, const uint8_t *iv16,
                             uint8_t *ctx, int ctx_size);
int chez_ssh_aes256_ctr_process(uint8_t *ctx, const uint8_t *in, int len,
                                uint8_t *out);
int chez_ssh_aes256_ctr_free(uint8_t *ctx);

/* ========== Ed25519 ========== */
int chez_ssh_ed25519_verify(const uint8_t *pubkey32,
                            const uint8_t *data, int datalen,
                            const uint8_t *sig64);
int chez_ssh_ed25519_sign(const uint8_t *seed32,
                          const uint8_t *data, int datalen,
                          uint8_t *sig64);
int chez_ssh_ed25519_derive_pubkey(const uint8_t *seed32, uint8_t *pubkey32);

/* ========== TCP Networking ========== */
int chez_ssh_tcp_connect(const char *host, int port);
int chez_ssh_tcp_read(int fd, uint8_t *buf, int maxlen);
int chez_ssh_tcp_write(int fd, const uint8_t *buf, int len);
int chez_ssh_tcp_close(int fd);
int chez_ssh_tcp_listen(const char *bind_addr, int port);
int chez_ssh_tcp_accept(int listen_fd);
int chez_ssh_tcp_set_nodelay(int fd, int enable);

#endif /* CHEZ_SSH_CRYPTO_H */
