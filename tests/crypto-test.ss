#!/usr/bin/env scheme-script
#!chezscheme

;;; Crypto primitive tests for chez_ssh_crypto.so
;;; Tests SHA-256, HMAC-SHA-256, Curve25519, ChaCha20-Poly1305, Ed25519, AES-256-CTR

(import (chezscheme))

;; Load crypto library
(load-shared-object "./chez_ssh_crypto.so")

;; FFI bindings
(define c-random-bytes
  (foreign-procedure "chez_ssh_random_bytes" (u8* int) int))
(define c-sha256
  (foreign-procedure "chez_ssh_sha256" (u8* int u8*) int))
(define c-sha512
  (foreign-procedure "chez_ssh_sha512" (u8* int u8*) int))
(define c-hmac-sha256
  (foreign-procedure "chez_ssh_hmac_sha256" (u8* int u8* int u8*) int))
(define c-hmac-sha512
  (foreign-procedure "chez_ssh_hmac_sha512" (u8* int u8* int u8*) int))
(define c-curve25519-keygen
  (foreign-procedure "chez_ssh_curve25519_keygen" (u8* u8*) int))
(define c-curve25519-shared-secret
  (foreign-procedure "chez_ssh_curve25519_shared_secret" (u8* u8* u8* u8*) int))
(define c-chacha20-poly1305-encrypt
  (foreign-procedure "chez_ssh_chacha20_poly1305_encrypt"
    (u8* unsigned-64 u8* int u8* u8*) int))
(define c-chacha20-poly1305-decrypt
  (foreign-procedure "chez_ssh_chacha20_poly1305_decrypt"
    (u8* unsigned-64 u8* int u8* u8*) int))
(define c-chacha20-poly1305-decrypt-length
  (foreign-procedure "chez_ssh_chacha20_poly1305_decrypt_length"
    (u8* unsigned-64 u8* u8*) int))
(define c-ed25519-sign
  (foreign-procedure "chez_ssh_ed25519_sign" (u8* u8* int u8*) int))
(define c-ed25519-verify
  (foreign-procedure "chez_ssh_ed25519_verify" (u8* u8* int u8*) int))
(define c-ed25519-derive-pubkey
  (foreign-procedure "chez_ssh_ed25519_derive_pubkey" (u8* u8*) int))
(define c-aes256-ctr-init
  (foreign-procedure "chez_ssh_aes256_ctr_init" (u8* u8* u8* int) int))
(define c-aes256-ctr-process
  (foreign-procedure "chez_ssh_aes256_ctr_process" (u8* u8* int u8*) int))
(define c-aes256-ctr-free
  (foreign-procedure "chez_ssh_aes256_ctr_free" (u8*) int))
(define c-tcp-connect
  (foreign-procedure "chez_ssh_tcp_connect" (string int) int))
(define c-tcp-close
  (foreign-procedure "chez_ssh_tcp_close" (int) int))

;; Test infrastructure
(define pass-count 0)
(define fail-count 0)

(define-syntax test
  (syntax-rules ()
    [(_ name expected actual)
     (let ([e expected] [a actual])
       (if (equal? e a)
         (begin (set! pass-count (+ pass-count 1))
                (printf "  PASS: ~a~n" name))
         (begin (set! fail-count (+ fail-count 1))
                (printf "  FAIL: ~a~n    expected: ~s~n    actual:   ~s~n" name e a))))]))

(define-syntax test-true
  (syntax-rules ()
    [(_ name actual)
     (let ([a actual])
       (if a
         (begin (set! pass-count (+ pass-count 1))
                (printf "  PASS: ~a~n" name))
         (begin (set! fail-count (+ fail-count 1))
                (printf "  FAIL: ~a (expected true)~n" name))))]))

(define (bytes->hex bv)
  (let ([out (make-string (* 2 (bytevector-length bv)))])
    (let loop ([i 0])
      (if (>= i (bytevector-length bv))
        out
        (let ([b (bytevector-u8-ref bv i)])
          (string-set! out (* i 2)
            (string-ref "0123456789abcdef" (bitwise-arithmetic-shift-right b 4)))
          (string-set! out (+ (* i 2) 1)
            (string-ref "0123456789abcdef" (bitwise-and b 15)))
          (loop (+ i 1)))))))

;; ---- Random ----
(printf "~n=== Random ===~n")

(let ([buf (make-bytevector 32 0)])
  (test "random returns 0" 0 (c-random-bytes buf 32))
  ;; Check it's not all zeros (extremely unlikely)
  (test-true "random not all zeros"
    (not (bytevector=? buf (make-bytevector 32 0)))))

;; ---- SHA-256 ----
(printf "~n=== SHA-256 ===~n")

;; SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
(let ([out (make-bytevector 32)])
  (test "sha256 empty rc" 0 (c-sha256 (make-bytevector 0) 0 out))
  (test "sha256 empty"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    (bytes->hex out)))

;; SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
(let ([out (make-bytevector 32)]
      [data (string->utf8 "abc")])
  (c-sha256 data 3 out)
  (test "sha256 abc"
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    (bytes->hex out)))

;; ---- SHA-512 ----
(printf "~n=== SHA-512 ===~n")

(let ([out (make-bytevector 64)])
  (test "sha512 empty rc" 0 (c-sha512 (make-bytevector 0) 0 out))
  (test "sha512 empty"
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    (bytes->hex out)))

;; ---- HMAC-SHA-256 ----
(printf "~n=== HMAC-SHA-256 ===~n")

;; RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
(let* ([key (string->utf8 "Jefe")]
       [data (string->utf8 "what do ya want for nothing?")]
       [out (make-bytevector 32)])
  (test "hmac-sha256 rc" 0
    (c-hmac-sha256 key (bytevector-length key) data (bytevector-length data) out))
  (test "hmac-sha256 rfc4231"
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    (bytes->hex out)))

;; ---- Curve25519 ECDH ----
(printf "~n=== Curve25519 ===~n")

(let ([priv1 (make-bytevector 32)]
      [pub1 (make-bytevector 32)]
      [priv2 (make-bytevector 32)]
      [pub2 (make-bytevector 32)]
      [secret1 (make-bytevector 32)]
      [secret2 (make-bytevector 32)]
      [len1 (make-bytevector 4 0)]
      [len2 (make-bytevector 4 0)])
  (test "curve25519 keygen1" 0 (c-curve25519-keygen priv1 pub1))
  (test "curve25519 keygen2" 0 (c-curve25519-keygen priv2 pub2))
  ;; Both sides should derive same shared secret
  (test "curve25519 dh1" 0 (c-curve25519-shared-secret priv1 pub2 secret1 len1))
  (test "curve25519 dh2" 0 (c-curve25519-shared-secret priv2 pub1 secret2 len2))
  (test-true "curve25519 shared secrets match"
    (bytevector=? secret1 secret2))
  (test-true "curve25519 secret not zero"
    (not (bytevector=? secret1 (make-bytevector 32 0)))))

;; ---- Ed25519 ----
(printf "~n=== Ed25519 ===~n")

(let ([seed (make-bytevector 32)]
      [pubkey (make-bytevector 32)]
      [sig (make-bytevector 64)]
      [data (string->utf8 "test message")])
  (c-random-bytes seed 32)
  (test "ed25519 derive pubkey" 0 (c-ed25519-derive-pubkey seed pubkey))
  (test "ed25519 sign" 0 (c-ed25519-sign seed data (bytevector-length data) sig))
  (test "ed25519 verify" 0 (c-ed25519-verify pubkey data (bytevector-length data) sig))
  ;; Corrupt signature — should fail
  (bytevector-u8-set! sig 0 (bitwise-xor (bytevector-u8-ref sig 0) #xff))
  (test "ed25519 verify bad sig" -1
    (c-ed25519-verify pubkey data (bytevector-length data) sig)))

;; ---- ChaCha20-Poly1305 ----
(printf "~n=== ChaCha20-Poly1305 ===~n")

(let* ([key (make-bytevector 64)]
       [_ (c-random-bytes key 64)]
       ;; plaintext: 4 bytes length + payload
       [payload (string->utf8 "Hello, SSH!")]
       [plen (bytevector-length payload)]
       [packet-length (+ 1 plen 4)]  ;; padding_len(1) + payload + padding(4)
       [plaintext (make-bytevector (+ 4 packet-length))]
       [seqno 42])
  ;; Build plaintext
  (bytevector-u8-set! plaintext 0 (bitwise-arithmetic-shift-right packet-length 24))
  (bytevector-u8-set! plaintext 1 (bitwise-and (bitwise-arithmetic-shift-right packet-length 16) #xff))
  (bytevector-u8-set! plaintext 2 (bitwise-and (bitwise-arithmetic-shift-right packet-length 8) #xff))
  (bytevector-u8-set! plaintext 3 (bitwise-and packet-length #xff))
  (bytevector-u8-set! plaintext 4 4)  ;; padding_length = 4
  (bytevector-copy! payload 0 plaintext 5 plen)
  ;; 4 bytes padding (zeros ok for test)

  ;; Encrypt
  (let ([enc-buf (make-bytevector (+ (bytevector-length plaintext) 16))]
        [enc-len-buf (make-bytevector 4 0)])
    (test "chacha20 encrypt rc" 0
      (c-chacha20-poly1305-encrypt key seqno plaintext (bytevector-length plaintext)
                                    enc-buf enc-len-buf))
    ;; Decrypt length
    (let ([dec-len-buf (make-bytevector 4)])
      (test "chacha20 decrypt-length rc" 0
        (c-chacha20-poly1305-decrypt-length key seqno enc-buf dec-len-buf))
      ;; Verify decrypted length matches
      (let ([dec-len (bitwise-ior
                       (bitwise-arithmetic-shift-left (bytevector-u8-ref dec-len-buf 0) 24)
                       (bitwise-arithmetic-shift-left (bytevector-u8-ref dec-len-buf 1) 16)
                       (bitwise-arithmetic-shift-left (bytevector-u8-ref dec-len-buf 2) 8)
                       (bytevector-u8-ref dec-len-buf 3))])
        (test "chacha20 length roundtrip" packet-length dec-len)))

    ;; Full decrypt
    (let* ([enc-total (car (let ([r (make-bytevector 4)])
                             (bytevector-copy! enc-len-buf 0 r 0 4)
                             (let ([n (bitwise-ior
                                        (bitwise-arithmetic-shift-left (bytevector-u8-ref r 0) 24)
                                        (bitwise-arithmetic-shift-left (bytevector-u8-ref r 1) 16)
                                        (bitwise-arithmetic-shift-left (bytevector-u8-ref r 2) 8)
                                        (bytevector-u8-ref r 3))])
                               (cons n 4))))]
           [ct-len (+ 4 packet-length 16)]
           [dec-buf (make-bytevector (+ 4 packet-length))]
           [dec-out-len-buf (make-bytevector 4 0)])
      (test "chacha20 decrypt rc" 0
        (c-chacha20-poly1305-decrypt key seqno enc-buf ct-len dec-buf dec-out-len-buf))
      ;; Verify payload matches
      (let ([dec-payload (make-bytevector plen)])
        (bytevector-copy! dec-buf 5 dec-payload 0 plen)
        (test "chacha20 roundtrip"
          "Hello, SSH!"
          (utf8->string dec-payload))))))

;; ---- AES-256-CTR ----
(printf "~n=== AES-256-CTR ===~n")

(let ([key (make-bytevector 32)]
      [iv (make-bytevector 16)]
      [ctx1 (make-bytevector 512)]
      [ctx2 (make-bytevector 512)]
      [data (string->utf8 "AES-256-CTR test data")])
  (c-random-bytes key 32)
  (c-random-bytes iv 16)
  ;; Encrypt
  (test "aes-ctr init enc" 0 (c-aes256-ctr-init key iv ctx1 512))
  (let ([enc (make-bytevector (bytevector-length data))])
    (test-true "aes-ctr encrypt"
      (> (c-aes256-ctr-process ctx1 data (bytevector-length data) enc) 0))
    ;; Decrypt with fresh context (same key/iv)
    (test "aes-ctr init dec" 0 (c-aes256-ctr-init key iv ctx2 512))
    (let ([dec (make-bytevector (bytevector-length data))])
      (test-true "aes-ctr decrypt"
        (> (c-aes256-ctr-process ctx2 enc (bytevector-length enc) dec) 0))
      (test "aes-ctr roundtrip"
        "AES-256-CTR test data"
        (utf8->string dec)))
    (c-aes256-ctr-free ctx1)
    (c-aes256-ctr-free ctx2)))

;; ---- TCP (basic) ----
(printf "~n=== TCP ===~n")

;; Test that connect to invalid address returns -1
(test "tcp connect bad host" -1 (c-tcp-connect "256.256.256.256" 22))

;; ---- Summary ----
(printf "~n=== Results ===~n")
(printf "~a passed, ~a failed~n" pass-count fail-count)
(when (> fail-count 0)
  (exit 1))
