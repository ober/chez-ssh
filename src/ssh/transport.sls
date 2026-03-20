#!chezscheme
;;; (ssh transport) — SSH transport layer
;;;
;;; TCP connect, version exchange, packet framing (encrypt/decrypt),
;;; sequence numbers, and rekey support.

(library (ssh transport)
  (export
    ;; Transport state
    make-transport-state
    transport-state?
    transport-state-fd
    transport-state-session-id
    transport-state-session-id-set!
    transport-state-server-version
    transport-state-client-version
    transport-state-send-seqno
    transport-state-send-seqno-set!
    transport-state-recv-seqno
    transport-state-recv-seqno-set!
    transport-state-send-cipher
    transport-state-recv-cipher
    transport-state-send-cipher-set!
    transport-state-recv-cipher-set!
    transport-state-send-mac-key
    transport-state-recv-mac-key
    transport-state-send-mac-key-set!
    transport-state-recv-mac-key-set!
    transport-state-client-kexinit
    transport-state-client-kexinit-set!
    transport-state-server-kexinit
    transport-state-server-kexinit-set!
    transport-state-algorithms
    transport-state-algorithms-set!
    transport-state-bytes-sent
    transport-state-bytes-sent-set!
    transport-state-bytes-received
    transport-state-bytes-received-set!
    transport-state-packets-sent
    transport-state-packets-sent-set!
    transport-state-packets-received
    transport-state-packets-received-set!

    ;; Cipher state
    make-cipher-state
    cipher-state?
    cipher-state-name
    cipher-state-key
    cipher-state-mac-key
    cipher-state-iv
    cipher-state-ctx

    ;; Negotiated algorithms
    make-negotiated-algorithms
    negotiated-algorithms?
    negotiated-algorithms-kex
    negotiated-algorithms-host-key
    negotiated-algorithms-cipher-c2s
    negotiated-algorithms-cipher-s2c
    negotiated-algorithms-mac-c2s
    negotiated-algorithms-mac-s2c
    negotiated-algorithms-compress-c2s
    negotiated-algorithms-compress-s2c

    ;; Connection and I/O
    ssh-transport-connect
    ssh-transport-close
    ssh-transport-send-version
    ssh-transport-recv-version
    ssh-transport-send-packet
    ssh-transport-recv-packet

    ;; Rekey thresholds
    ssh-transport-needs-rekey?

    ;; Low-level TCP I/O
    ssh-tcp-read-exact
    ssh-tcp-write-all
    )

  (import (chezscheme) (ssh wire))

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

  ;; ---- FFI bindings ----
  (define c-tcp-connect
    (foreign-procedure "chez_ssh_tcp_connect" (string int) int))
  (define c-tcp-read
    (foreign-procedure "chez_ssh_tcp_read" (int u8* int) int))
  (define c-tcp-write
    (foreign-procedure "chez_ssh_tcp_write" (int u8* int) int))
  (define c-tcp-close
    (foreign-procedure "chez_ssh_tcp_close" (int) int))
  (define c-tcp-set-nodelay
    (foreign-procedure "chez_ssh_tcp_set_nodelay" (int int) int))
  (define c-random-bytes
    (foreign-procedure "chez_ssh_random_bytes" (u8* int) int))
  (define c-hmac-sha256
    (foreign-procedure "chez_ssh_hmac_sha256" (u8* int u8* int u8*) int))

  ;; ChaCha20-Poly1305
  (define c-chacha20-poly1305-encrypt
    (foreign-procedure "chez_ssh_chacha20_poly1305_encrypt"
      (u8* unsigned-64 u8* int u8* u8*) int))
  (define c-chacha20-poly1305-decrypt
    (foreign-procedure "chez_ssh_chacha20_poly1305_decrypt"
      (u8* unsigned-64 u8* int u8* u8*) int))
  (define c-chacha20-poly1305-decrypt-length
    (foreign-procedure "chez_ssh_chacha20_poly1305_decrypt_length"
      (u8* unsigned-64 u8* u8*) int))

  ;; AES-256-CTR
  (define c-aes256-ctr-init
    (foreign-procedure "chez_ssh_aes256_ctr_init" (u8* u8* u8* int) int))
  (define c-aes256-ctr-process
    (foreign-procedure "chez_ssh_aes256_ctr_process" (u8* u8* int u8*) int))
  (define c-aes256-ctr-free
    (foreign-procedure "chez_ssh_aes256_ctr_free" (u8*) int))

  ;; ---- Constants ----
  (define CLIENT-VERSION "SSH-2.0-chez-ssh_1.0")
  (define MAX-PACKET-SIZE 262144)   ;; 256 KB
  (define REKEY-BYTES-THRESHOLD (* 1024 1024 1024))  ;; 1 GB
  (define REKEY-PACKETS-THRESHOLD (* 1024 1024))      ;; 1M packets

  ;; ---- Records ----

  (define-record-type cipher-state
    (fields
      name       ;; string: "chacha20-poly1305@openssh.com" or "aes256-ctr"
      key        ;; bytevector: cipher key (64 for chacha, 32 for aes)
      mac-key    ;; bytevector or #f: HMAC key (for aes256-ctr)
      iv         ;; bytevector or #f: IV (for aes256-ctr)
      ctx))      ;; bytevector or #f: AES context buffer

  (define-record-type negotiated-algorithms
    (fields
      kex             ;; string
      host-key        ;; string
      cipher-c2s      ;; string
      cipher-s2c      ;; string
      mac-c2s         ;; string
      mac-s2c         ;; string
      compress-c2s    ;; string
      compress-s2c))  ;; string

  (define-record-type transport-state
    (fields
      fd                ;; int: TCP socket fd
      (mutable session-id)      ;; bytevector or #f
      server-version    ;; string
      client-version    ;; string
      (mutable send-seqno)      ;; int
      (mutable recv-seqno)      ;; int
      (mutable send-cipher)     ;; cipher-state or #f
      (mutable recv-cipher)     ;; cipher-state or #f
      (mutable send-mac-key)    ;; bytevector or #f
      (mutable recv-mac-key)    ;; bytevector or #f
      (mutable client-kexinit)  ;; bytevector or #f (raw KEXINIT payload)
      (mutable server-kexinit)  ;; bytevector or #f
      (mutable algorithms)      ;; negotiated-algorithms or #f
      (mutable bytes-sent)      ;; int
      (mutable bytes-received)  ;; int
      (mutable packets-sent)    ;; int
      (mutable packets-received)) ;; int
    (protocol
      (lambda (new)
        (lambda (fd server-version client-version)
          (new fd #f server-version client-version
               0 0 #f #f #f #f #f #f #f 0 0 0 0)))))

  ;; ---- Low-level TCP I/O ----

  (define (ssh-tcp-read-exact fd n)
    (let ([buf (make-bytevector n)])
      (let loop ([off 0])
        (if (>= off n)
          buf
          (let* ([remaining (- n off)]
                 [tmp (make-bytevector remaining)]
                 [got (c-tcp-read fd tmp remaining)])
            (when (<= got 0)
              (error 'ssh-tcp-read-exact "connection closed" off n))
            (bytevector-copy! tmp 0 buf off got)
            (loop (+ off got)))))))

  (define (ssh-tcp-write-all fd bv)
    (let ([rc (c-tcp-write fd bv (bytevector-length bv))])
      (when (< rc 0)
        (error 'ssh-tcp-write-all "write failed"))
      rc))

  ;; ---- Connection ----

  (define (ssh-transport-connect host port)
    (let ([fd (c-tcp-connect host port)])
      (when (< fd 0)
        (error 'ssh-transport-connect "connection failed" host port))
      (c-tcp-set-nodelay fd 1)
      fd))

  (define (ssh-transport-close ts)
    (c-tcp-close (transport-state-fd ts)))

  ;; ---- Version exchange ----

  (define (ssh-transport-send-version fd)
    (let ([line (string-append CLIENT-VERSION "\r\n")])
      (ssh-tcp-write-all fd (string->utf8 line))
      CLIENT-VERSION))

  (define (ssh-transport-recv-version fd)
    ;; Read lines until we get one starting with "SSH-2.0-"
    ;; Lines are \r\n terminated, max 255 chars per RFC 4253
    (let loop ([lines-read 0])
      (when (> lines-read 20)
        (error 'ssh-transport-recv-version "too many banner lines"))
      (let line-loop ([acc '()] [count 0])
        (when (> count 255)
          (error 'ssh-transport-recv-version "line too long"))
        (let* ([tmp (make-bytevector 1)]
               [got (c-tcp-read fd tmp 1)])
          (when (<= got 0)
            (error 'ssh-transport-recv-version "connection closed"))
          (let ([ch (bytevector-u8-ref tmp 0)])
            (cond
              [(= ch 10)  ;; \n — end of line
               (let* ([bytes (u8-list->bytevector (reverse acc))]
                      [line (utf8->string bytes)]
                      ;; Strip trailing \r if present
                      [line (if (and (> (string-length line) 0)
                                     (char=? (string-ref line (- (string-length line) 1)) #\return))
                              (substring line 0 (- (string-length line) 1))
                              line)])
                 (if (and (>= (string-length line) 8)
                          (string=? (substring line 0 4) "SSH-"))
                   line
                   (loop (+ lines-read 1))))]
              [else
               (line-loop (cons ch acc) (+ count 1))]))))))

  ;; ---- Packet framing ----

  ;; Unencrypted packet format (RFC 4253 §6):
  ;;   uint32  packet_length  (not including itself or MAC)
  ;;   byte    padding_length
  ;;   byte[]  payload
  ;;   byte[]  random padding (at least 4 bytes)
  ;;   byte[]  MAC (if any)
  ;; Total (packet_length + 4) must be multiple of block size (8 for none)

  ;; -- Unencrypted packets --

  (define (send-packet-unencrypted ts payload)
    (let* ([plen (bytevector-length payload)]
           [block-size 8]
           ;; padding: at least 4 bytes, total (4 + 1 + plen + padding) must be multiple of block-size
           [min-pad 4]
           [base (+ 5 plen)]  ;; 4(len) + 1(padlen) + payload
           [padding-len (let ([rem (modulo base block-size)])
                          (let ([pad (if (= rem 0) 0 (- block-size rem))])
                            (if (< pad min-pad) (+ pad block-size) pad)))]
           [packet-length (+ 1 plen padding-len)]
           [total (+ 4 packet-length)]
           [pkt (make-bytevector total)])
      ;; Fill packet_length
      (let ([hdr (ssh-write-uint32 packet-length)])
        (bytevector-copy! hdr 0 pkt 0 4))
      ;; padding_length
      (bytevector-u8-set! pkt 4 padding-len)
      ;; payload
      (bytevector-copy! payload 0 pkt 5 plen)
      ;; random padding
      (let ([pad (make-bytevector padding-len)])
        (c-random-bytes pad padding-len)
        (bytevector-copy! pad 0 pkt (+ 5 plen) padding-len))
      ;; Send
      (ssh-tcp-write-all (transport-state-fd ts) pkt)
      ;; Update counters
      (transport-state-send-seqno-set! ts
        (bitwise-and (+ (transport-state-send-seqno ts) 1) #xFFFFFFFF))
      (transport-state-bytes-sent-set! ts
        (+ (transport-state-bytes-sent ts) total))
      (transport-state-packets-sent-set! ts
        (+ (transport-state-packets-sent ts) 1))))

  (define (recv-packet-unencrypted ts)
    (let* ([fd (transport-state-fd ts)]
           [hdr (ssh-tcp-read-exact fd 4)]
           [pkt-len (car (ssh-read-uint32 hdr 0))])
      (when (or (< pkt-len 2) (> pkt-len MAX-PACKET-SIZE))
        (error 'recv-packet-unencrypted "invalid packet length" pkt-len))
      (let* ([data (ssh-tcp-read-exact fd pkt-len)]
             [pad-len (bytevector-u8-ref data 0)]
             [payload-len (- pkt-len 1 pad-len)]
             [payload (make-bytevector payload-len)])
        (when (< payload-len 0)
          (error 'recv-packet-unencrypted "invalid padding" pad-len pkt-len))
        (bytevector-copy! data 1 payload 0 payload-len)
        ;; Update counters
        (transport-state-recv-seqno-set! ts
          (bitwise-and (+ (transport-state-recv-seqno ts) 1) #xFFFFFFFF))
        (transport-state-bytes-received-set! ts
          (+ (transport-state-bytes-received ts) (+ 4 pkt-len)))
        (transport-state-packets-received-set! ts
          (+ (transport-state-packets-received ts) 1))
        payload)))

  ;; -- ChaCha20-Poly1305 encrypted packets --

  (define (send-packet-chacha20 ts payload)
    (let* ([plen (bytevector-length payload)]
           [block-size 8]
           [min-pad 4]
           [base (+ 1 plen)]
           [padding-len (let ([rem (modulo base block-size)])
                          (let ([pad (if (= rem 0) 0 (- block-size rem))])
                            (if (< pad min-pad) (+ pad block-size) pad)))]
           [packet-length (+ 1 plen padding-len)]
           ;; Build plaintext: uint32(packet_length) || padding_len || payload || padding
           [plain (make-bytevector (+ 4 packet-length))]
           [seqno (transport-state-send-seqno ts)]
           [key (cipher-state-key (transport-state-send-cipher ts))])
      ;; Write packet_length
      (let ([hdr (ssh-write-uint32 packet-length)])
        (bytevector-copy! hdr 0 plain 0 4))
      (bytevector-u8-set! plain 4 padding-len)
      (bytevector-copy! payload 0 plain 5 plen)
      (let ([pad (make-bytevector padding-len)])
        (c-random-bytes pad padding-len)
        (bytevector-copy! pad 0 plain (+ 5 plen) padding-len))
      ;; Encrypt
      (let* ([out-buf (make-bytevector (+ (bytevector-length plain) 16))]
             [out-len-buf (make-bytevector 4 0)]  ;; to receive out_len as int
             [rc (c-chacha20-poly1305-encrypt key seqno
                   plain (bytevector-length plain) out-buf out-len-buf)])
        (when (< rc 0)
          (error 'send-packet-chacha20 "encryption failed"))
        (let ([out-len (car (ssh-read-uint32 out-len-buf 0))])
          (let ([final (make-bytevector out-len)])
            (bytevector-copy! out-buf 0 final 0 out-len)
            (ssh-tcp-write-all (transport-state-fd ts) final)
            (transport-state-send-seqno-set! ts
              (bitwise-and (+ seqno 1) #xFFFFFFFF))
            (transport-state-bytes-sent-set! ts
              (+ (transport-state-bytes-sent ts) out-len))
            (transport-state-packets-sent-set! ts
              (+ (transport-state-packets-sent ts) 1)))))))

  (define (recv-packet-chacha20 ts)
    (let* ([fd (transport-state-fd ts)]
           [seqno (transport-state-recv-seqno ts)]
           [key (cipher-state-key (transport-state-recv-cipher ts))]
           [enc-len-bytes (ssh-tcp-read-exact fd 4)]
           [len-buf (make-bytevector 4)]
           [rc (c-chacha20-poly1305-decrypt-length key seqno enc-len-bytes len-buf)])
      (when (< rc 0)
        (error 'recv-packet-chacha20 "length decryption failed"))
      (let* ([pkt-len (car (ssh-read-uint32 len-buf 0))])
        (when (or (< pkt-len 2) (> pkt-len MAX-PACKET-SIZE))
          (error 'recv-packet-chacha20 "invalid packet length" pkt-len))
        (let* ([enc-payload+tag (ssh-tcp-read-exact fd (+ pkt-len 16))]
               [full-ct (make-bytevector (+ 4 pkt-len 16))]
               [out-buf (make-bytevector (+ 4 pkt-len))]
               [out-len-buf (make-bytevector 4 0)])
          (bytevector-copy! enc-len-bytes 0 full-ct 0 4)
          (bytevector-copy! enc-payload+tag 0 full-ct 4 (+ pkt-len 16))
          (let ([rc2 (c-chacha20-poly1305-decrypt key seqno
                       full-ct (bytevector-length full-ct) out-buf out-len-buf)])
            (when (< rc2 0)
              (error 'recv-packet-chacha20 "decryption/authentication failed"))
            (let* ([pad-len (bytevector-u8-ref out-buf 4)]
                   [payload-len (- pkt-len 1 pad-len)]
                   [payload (make-bytevector payload-len)])
              (when (< payload-len 0)
                (error 'recv-packet-chacha20 "invalid padding"))
              (bytevector-copy! out-buf 5 payload 0 payload-len)
              (transport-state-recv-seqno-set! ts
                (bitwise-and (+ seqno 1) #xFFFFFFFF))
              (transport-state-bytes-received-set! ts
                (+ (transport-state-bytes-received ts) (+ 4 pkt-len 16)))
              (transport-state-packets-received-set! ts
                (+ (transport-state-packets-received ts) 1))
              payload))))))

  ;; -- AES-256-CTR + HMAC-SHA2-256 encrypted packets --

  (define (send-packet-aes256-ctr ts payload)
    (let* ([plen (bytevector-length payload)]
           [block-size 16]
           [min-pad 4]
           [base (+ 5 plen)]
           [padding-len (let ([rem (modulo base block-size)])
                          (let ([pad (if (= rem 0) 0 (- block-size rem))])
                            (if (< pad min-pad) (+ pad block-size) pad)))]
           [packet-length (+ 1 plen padding-len)]
           ;; Build unencrypted content: uint32(packet_length) || padding_len || payload || padding
           [plain (make-bytevector (+ 4 packet-length))]
           [seqno (transport-state-send-seqno ts)]
           [cipher (transport-state-send-cipher ts)])
      (let ([hdr (ssh-write-uint32 packet-length)])
        (bytevector-copy! hdr 0 plain 0 4))
      (bytevector-u8-set! plain 4 padding-len)
      (bytevector-copy! payload 0 plain 5 plen)
      (let ([pad (make-bytevector padding-len)])
        (c-random-bytes pad padding-len)
        (bytevector-copy! pad 0 plain (+ 5 plen) padding-len))
      ;; Compute MAC over seqno || unencrypted_packet
      (let* ([mac-data-len (+ 4 (bytevector-length plain))]
             [mac-data (make-bytevector mac-data-len)]
             [seqno-bv (ssh-write-uint32 seqno)]
             [mac-out (make-bytevector 32)])
        (bytevector-copy! seqno-bv 0 mac-data 0 4)
        (bytevector-copy! plain 0 mac-data 4 (bytevector-length plain))
        (let ([mac-key (cipher-state-mac-key cipher)])
          (when mac-key
            (c-hmac-sha256 mac-key (bytevector-length mac-key)
                           mac-data mac-data-len mac-out)))
        ;; Encrypt the packet (including length field)
        (let* ([enc-buf (make-bytevector (bytevector-length plain))]
               [ctx-buf (cipher-state-ctx cipher)]
               [enc-len (c-aes256-ctr-process ctx-buf plain (bytevector-length plain) enc-buf)])
          (when (< enc-len 0)
            (error 'send-packet-aes256-ctr "encryption failed"))
          ;; Send encrypted data + MAC
          (ssh-tcp-write-all (transport-state-fd ts) enc-buf)
          (when (cipher-state-mac-key cipher)
            (ssh-tcp-write-all (transport-state-fd ts) mac-out))
          (transport-state-send-seqno-set! ts
            (bitwise-and (+ seqno 1) #xFFFFFFFF))
          (transport-state-bytes-sent-set! ts
            (+ (transport-state-bytes-sent ts) (+ (bytevector-length enc-buf) 32)))
          (transport-state-packets-sent-set! ts
            (+ (transport-state-packets-sent ts) 1))))))

  (define (recv-packet-aes256-ctr ts)
    (let* ([fd (transport-state-fd ts)]
           [seqno (transport-state-recv-seqno ts)]
           [cipher (transport-state-recv-cipher ts)]
           [ctx-buf (cipher-state-ctx cipher)]
           ;; Read and decrypt first 16 bytes (one AES block) to get packet_length
           [enc-first (ssh-tcp-read-exact fd 16)]
           [dec-first (make-bytevector 16)]
           [_ (let ([rc (c-aes256-ctr-process ctx-buf enc-first 16 dec-first)])
                (when (< rc 0) (error 'recv-packet-aes256-ctr "decrypt failed")))]
           [pkt-len (car (ssh-read-uint32 dec-first 0))])
      (when (or (< pkt-len 2) (> pkt-len MAX-PACKET-SIZE))
        (error 'recv-packet-aes256-ctr "invalid packet length" pkt-len))
      ;; Read remaining encrypted bytes: (4 + pkt-len) - 16 already read
      (let* ([total-encrypted (+ 4 pkt-len)]
             [remaining (- total-encrypted 16)])
        (let* ([dec-rest (if (> remaining 0)
                           (let* ([enc-rest (ssh-tcp-read-exact fd remaining)]
                                  [dec-buf (make-bytevector remaining)]
                                  [rc (c-aes256-ctr-process ctx-buf enc-rest remaining dec-buf)])
                             (when (< rc 0) (error 'recv-packet-aes256-ctr "decrypt failed"))
                             dec-buf)
                           (make-bytevector 0))]
               ;; Reassemble full decrypted packet
               [full (make-bytevector total-encrypted)]
               [_ (begin
                    (bytevector-copy! dec-first 0 full 0 16)
                    (when (> remaining 0)
                      (bytevector-copy! dec-rest 0 full 16 remaining)))]
               ;; Read and verify MAC (32 bytes for hmac-sha2-256)
               [mac-received (ssh-tcp-read-exact fd 32)]
               ;; Compute expected MAC
               [mac-data-len (+ 4 total-encrypted)]
               [mac-data (make-bytevector mac-data-len)]
               [seqno-bv (ssh-write-uint32 seqno)]
               [mac-expected (make-bytevector 32)])
          (bytevector-copy! seqno-bv 0 mac-data 0 4)
          (bytevector-copy! full 0 mac-data 4 total-encrypted)
          (let ([mac-key (cipher-state-mac-key cipher)])
            (when mac-key
              (c-hmac-sha256 mac-key (bytevector-length mac-key)
                             mac-data mac-data-len mac-expected)
              (unless (bytevector=? mac-received mac-expected)
                (error 'recv-packet-aes256-ctr "MAC verification failed"))))
          ;; Extract payload
          (let* ([pad-len (bytevector-u8-ref full 4)]
                 [payload-len (- pkt-len 1 pad-len)]
                 [payload (make-bytevector payload-len)])
            (when (< payload-len 0)
              (error 'recv-packet-aes256-ctr "invalid padding"))
            (bytevector-copy! full 5 payload 0 payload-len)
            (transport-state-recv-seqno-set! ts
              (bitwise-and (+ seqno 1) #xFFFFFFFF))
            (transport-state-bytes-received-set! ts
              (+ (transport-state-bytes-received ts) (+ total-encrypted 32)))
            (transport-state-packets-received-set! ts
              (+ (transport-state-packets-received ts) 1))
            payload)))))

  ;; ---- Packet dispatch ----

  (define (ssh-transport-send-packet ts payload)
    (let* ([cipher (transport-state-send-cipher ts)]
           [cipher-name (and cipher (cipher-state-name cipher))])
      (cond
        [(and cipher-name (string=? cipher-name "chacha20-poly1305@openssh.com"))
         (send-packet-chacha20 ts payload)]
        [(and cipher-name (string=? cipher-name "aes256-ctr"))
         (send-packet-aes256-ctr ts payload)]
        [else
         (send-packet-unencrypted ts payload)])))

  (define (ssh-transport-recv-packet ts)
    (let* ([cipher (transport-state-recv-cipher ts)]
           [cipher-name (and cipher (cipher-state-name cipher))])
      (cond
        [(and cipher-name (string=? cipher-name "chacha20-poly1305@openssh.com"))
         (recv-packet-chacha20 ts)]
        [(and cipher-name (string=? cipher-name "aes256-ctr"))
         (recv-packet-aes256-ctr ts)]
        [else
         (recv-packet-unencrypted ts)])))

  ;; ---- Rekey check ----

  (define (ssh-transport-needs-rekey? ts)
    (or (> (transport-state-bytes-sent ts) REKEY-BYTES-THRESHOLD)
        (> (transport-state-bytes-received ts) REKEY-BYTES-THRESHOLD)
        (> (transport-state-packets-sent ts) REKEY-PACKETS-THRESHOLD)
        (> (transport-state-packets-received ts) REKEY-PACKETS-THRESHOLD)))

  ) ;; end library
