#!chezscheme
;;; (chez-ssh crypto) — FFI bindings for SSH cryptographic and TCP operations
;;;
;;; This module contains ONLY foreign-procedure declarations wrapping
;;; the C shim libraries (chez_ssh_crypto.so). No protocol logic.
;;; Protocol logic lives in jerboa's (std net ssh ...) modules.

(library (chez-ssh crypto)
  (export
    ;; TCP operations
    ssh-crypto-tcp-connect       ;; (host port) -> fd
    ssh-crypto-tcp-read          ;; (fd buf len) -> bytes-read
    ssh-crypto-tcp-write         ;; (fd buf len) -> bytes-written
    ssh-crypto-tcp-close         ;; (fd) -> rc
    ssh-crypto-tcp-set-nodelay   ;; (fd flag) -> rc
    ssh-crypto-tcp-listen        ;; (addr port) -> fd
    ssh-crypto-tcp-accept        ;; (fd) -> client-fd

    ;; Random
    ssh-crypto-random-bytes      ;; (buf len) -> rc

    ;; Hashing
    ssh-crypto-sha256            ;; (data len out) -> rc
    ssh-crypto-hmac-sha256       ;; (key keylen data datalen out) -> rc

    ;; Curve25519 ECDH
    ssh-crypto-curve25519-keygen          ;; (priv pub) -> rc
    ssh-crypto-curve25519-shared-secret   ;; (priv peer secret len-buf) -> rc

    ;; Ed25519
    ssh-crypto-ed25519-sign              ;; (seed data datalen sig) -> rc
    ssh-crypto-ed25519-verify            ;; (pubkey data datalen sig) -> rc
    ssh-crypto-ed25519-derive-pubkey     ;; (seed pubkey) -> rc

    ;; ChaCha20-Poly1305
    ssh-crypto-chacha20-poly1305-encrypt         ;; (key seqno plain len out outlen) -> rc
    ssh-crypto-chacha20-poly1305-decrypt         ;; (key seqno ct len out outlen) -> rc
    ssh-crypto-chacha20-poly1305-decrypt-length  ;; (key seqno enclen out) -> rc

    ;; AES-256-CTR
    ssh-crypto-aes256-ctr-init      ;; (key iv ctx ctxlen) -> rc
    ssh-crypto-aes256-ctr-process   ;; (ctx in len out) -> rc
    ssh-crypto-aes256-ctr-free      ;; (ctx) -> rc
    )

  (import (chezscheme))

  ;; Load the crypto shared library
  (define _crypto
    (guard (e [#t (void)])
      (load-shared-object "chez_ssh_crypto.so")))
  (define _crypto-local
    (guard (e [#t (void)])
      (cond
        [(file-exists? "./chez_ssh_crypto.so")
         (load-shared-object "./chez_ssh_crypto.so")]
        [else (void)])))

  ;; ---- TCP operations ----

  (define ssh-crypto-tcp-connect
    (foreign-procedure "chez_ssh_tcp_connect" (string int) int))

  (define ssh-crypto-tcp-read
    (foreign-procedure "chez_ssh_tcp_read" (int u8* int) int))

  (define ssh-crypto-tcp-write
    (foreign-procedure "chez_ssh_tcp_write" (int u8* int) int))

  (define ssh-crypto-tcp-close
    (foreign-procedure "chez_ssh_tcp_close" (int) int))

  (define ssh-crypto-tcp-set-nodelay
    (foreign-procedure "chez_ssh_tcp_set_nodelay" (int int) int))

  (define ssh-crypto-tcp-listen
    (foreign-procedure "chez_ssh_tcp_listen" (string int) int))

  (define ssh-crypto-tcp-accept
    (foreign-procedure "chez_ssh_tcp_accept" (int) int))

  ;; ---- Random ----

  (define ssh-crypto-random-bytes
    (foreign-procedure "chez_ssh_random_bytes" (u8* int) int))

  ;; ---- Hashing ----

  (define ssh-crypto-sha256
    (foreign-procedure "chez_ssh_sha256" (u8* int u8*) int))

  (define ssh-crypto-hmac-sha256
    (foreign-procedure "chez_ssh_hmac_sha256" (u8* int u8* int u8*) int))

  ;; ---- Curve25519 ECDH ----

  (define ssh-crypto-curve25519-keygen
    (foreign-procedure "chez_ssh_curve25519_keygen" (u8* u8*) int))

  (define ssh-crypto-curve25519-shared-secret
    (foreign-procedure "chez_ssh_curve25519_shared_secret" (u8* u8* u8* u8*) int))

  ;; ---- Ed25519 ----

  (define ssh-crypto-ed25519-sign
    (foreign-procedure "chez_ssh_ed25519_sign" (u8* u8* int u8*) int))

  (define ssh-crypto-ed25519-verify
    (foreign-procedure "chez_ssh_ed25519_verify" (u8* u8* int u8*) int))

  (define ssh-crypto-ed25519-derive-pubkey
    (foreign-procedure "chez_ssh_ed25519_derive_pubkey" (u8* u8*) int))

  ;; ---- ChaCha20-Poly1305 ----

  (define ssh-crypto-chacha20-poly1305-encrypt
    (foreign-procedure "chez_ssh_chacha20_poly1305_encrypt"
      (u8* unsigned-64 u8* int u8* u8*) int))

  (define ssh-crypto-chacha20-poly1305-decrypt
    (foreign-procedure "chez_ssh_chacha20_poly1305_decrypt"
      (u8* unsigned-64 u8* int u8* u8*) int))

  (define ssh-crypto-chacha20-poly1305-decrypt-length
    (foreign-procedure "chez_ssh_chacha20_poly1305_decrypt_length"
      (u8* unsigned-64 u8* u8*) int))

  ;; ---- AES-256-CTR ----

  (define ssh-crypto-aes256-ctr-init
    (foreign-procedure "chez_ssh_aes256_ctr_init" (u8* u8* u8* int) int))

  (define ssh-crypto-aes256-ctr-process
    (foreign-procedure "chez_ssh_aes256_ctr_process" (u8* u8* int u8*) int))

  (define ssh-crypto-aes256-ctr-free
    (foreign-procedure "chez_ssh_aes256_ctr_free" (u8*) int))

  ) ;; end library
