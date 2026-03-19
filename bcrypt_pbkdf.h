/*
 * bcrypt_pbkdf.h — bcrypt-based PBKDF for OpenSSH encrypted keys
 *
 * Standalone implementation (no OpenSSL dependency).
 * Based on the OpenBSD bcrypt_pbkdf algorithm.
 */

#ifndef BCRYPT_PBKDF_H
#define BCRYPT_PBKDF_H

#include <stdint.h>
#include <stddef.h>

/*
 * bcrypt_pbkdf — Derive key material from a passphrase and salt.
 *
 * Used by OpenSSH encrypted private key format (cipher "aes256-ctr",
 * kdf "bcrypt"). Derives keylen bytes into key[] using the given
 * number of rounds.
 *
 * Returns 0 on success, -1 on error.
 */
int bcrypt_pbkdf(const char *pass, size_t passlen,
                 const uint8_t *salt, size_t saltlen,
                 unsigned int rounds,
                 uint8_t *key, size_t keylen);

#endif /* BCRYPT_PBKDF_H */
