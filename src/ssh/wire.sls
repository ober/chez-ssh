#!chezscheme
;;; (ssh wire) — SSH binary wire format primitives
;;;
;;; Provides read/write for SSH wire types (RFC 4251):
;;;   uint32, string, mpint, name-list, boolean, byte
;;; Plus SSH message type constants (RFC 4250, 4252, 4254).

(library (ssh wire)
  (export
    ;; Wire format writers (return bytevector)
    ssh-write-uint32
    ssh-write-string
    ssh-write-mpint
    ssh-write-name-list
    ssh-write-boolean
    ssh-write-byte

    ;; Wire format readers (consume from bytevector at offset, return (value . new-offset))
    ssh-read-uint32
    ssh-read-string
    ssh-read-mpint
    ssh-read-name-list
    ssh-read-boolean
    ssh-read-byte

    ;; Packet assembly
    ssh-make-payload     ;; (msg-type part ...) → bytevector

    ;; Message type constants — Transport (RFC 4253)
    SSH_MSG_DISCONNECT
    SSH_MSG_IGNORE
    SSH_MSG_UNIMPLEMENTED
    SSH_MSG_DEBUG
    SSH_MSG_SERVICE_REQUEST
    SSH_MSG_SERVICE_ACCEPT
    SSH_MSG_KEXINIT
    SSH_MSG_NEWKEYS

    ;; Key exchange (RFC 4253 + curve25519)
    SSH_MSG_KEX_ECDH_INIT
    SSH_MSG_KEX_ECDH_REPLY

    ;; User auth (RFC 4252)
    SSH_MSG_USERAUTH_REQUEST
    SSH_MSG_USERAUTH_FAILURE
    SSH_MSG_USERAUTH_SUCCESS
    SSH_MSG_USERAUTH_BANNER
    SSH_MSG_USERAUTH_INFO_REQUEST
    SSH_MSG_USERAUTH_INFO_RESPONSE

    ;; Channel (RFC 4254)
    SSH_MSG_GLOBAL_REQUEST
    SSH_MSG_REQUEST_SUCCESS
    SSH_MSG_REQUEST_FAILURE
    SSH_MSG_CHANNEL_OPEN
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    SSH_MSG_CHANNEL_OPEN_FAILURE
    SSH_MSG_CHANNEL_WINDOW_ADJUST
    SSH_MSG_CHANNEL_DATA
    SSH_MSG_CHANNEL_EXTENDED_DATA
    SSH_MSG_CHANNEL_EOF
    SSH_MSG_CHANNEL_CLOSE
    SSH_MSG_CHANNEL_REQUEST
    SSH_MSG_CHANNEL_SUCCESS
    SSH_MSG_CHANNEL_FAILURE

    ;; Disconnect reason codes
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    SSH_DISCONNECT_PROTOCOL_ERROR
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED
    SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED
    SSH_DISCONNECT_MAC_ERROR
    SSH_DISCONNECT_COMPRESSION_ERROR
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
    SSH_DISCONNECT_CONNECTION_LOST
    SSH_DISCONNECT_BY_APPLICATION
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
    SSH_DISCONNECT_ILLEGAL_USER_NAME

    ;; Extended data types
    SSH_EXTENDED_DATA_STDERR
    )

  (import (chezscheme))

  ;; ---- Message type constants ----

  ;; Transport layer (RFC 4253)
  (define SSH_MSG_DISCONNECT           1)
  (define SSH_MSG_IGNORE               2)
  (define SSH_MSG_UNIMPLEMENTED        3)
  (define SSH_MSG_DEBUG                4)
  (define SSH_MSG_SERVICE_REQUEST      5)
  (define SSH_MSG_SERVICE_ACCEPT       6)
  (define SSH_MSG_KEXINIT              20)
  (define SSH_MSG_NEWKEYS              21)

  ;; Key exchange — ECDH (RFC 5656 / curve25519-sha256)
  (define SSH_MSG_KEX_ECDH_INIT        30)
  (define SSH_MSG_KEX_ECDH_REPLY       31)

  ;; User auth (RFC 4252)
  (define SSH_MSG_USERAUTH_REQUEST     50)
  (define SSH_MSG_USERAUTH_FAILURE     51)
  (define SSH_MSG_USERAUTH_SUCCESS     52)
  (define SSH_MSG_USERAUTH_BANNER      53)
  (define SSH_MSG_USERAUTH_INFO_REQUEST  60)
  (define SSH_MSG_USERAUTH_INFO_RESPONSE 61)

  ;; Channels (RFC 4254)
  (define SSH_MSG_GLOBAL_REQUEST       80)
  (define SSH_MSG_REQUEST_SUCCESS      81)
  (define SSH_MSG_REQUEST_FAILURE      82)
  (define SSH_MSG_CHANNEL_OPEN         90)
  (define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91)
  (define SSH_MSG_CHANNEL_OPEN_FAILURE 92)
  (define SSH_MSG_CHANNEL_WINDOW_ADJUST 93)
  (define SSH_MSG_CHANNEL_DATA         94)
  (define SSH_MSG_CHANNEL_EXTENDED_DATA 95)
  (define SSH_MSG_CHANNEL_EOF          96)
  (define SSH_MSG_CHANNEL_CLOSE        97)
  (define SSH_MSG_CHANNEL_REQUEST      98)
  (define SSH_MSG_CHANNEL_SUCCESS      99)
  (define SSH_MSG_CHANNEL_FAILURE      100)

  ;; Disconnect reason codes
  (define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT        1)
  (define SSH_DISCONNECT_PROTOCOL_ERROR                     2)
  (define SSH_DISCONNECT_KEY_EXCHANGE_FAILED                3)
  (define SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED         4)
  (define SSH_DISCONNECT_MAC_ERROR                          5)
  (define SSH_DISCONNECT_COMPRESSION_ERROR                  6)
  (define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE              7)
  (define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED     8)
  (define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE            9)
  (define SSH_DISCONNECT_CONNECTION_LOST                    10)
  (define SSH_DISCONNECT_BY_APPLICATION                     11)
  (define SSH_DISCONNECT_TOO_MANY_CONNECTIONS               12)
  (define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER             13)
  (define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE     14)
  (define SSH_DISCONNECT_ILLEGAL_USER_NAME                  15)

  ;; Extended data types
  (define SSH_EXTENDED_DATA_STDERR     1)

  ;; ---- Wire format writers ----

  (define (ssh-write-uint32 n)
    (let ([bv (make-bytevector 4)])
      (bytevector-u8-set! bv 0 (bitwise-and (bitwise-arithmetic-shift-right n 24) #xff))
      (bytevector-u8-set! bv 1 (bitwise-and (bitwise-arithmetic-shift-right n 16) #xff))
      (bytevector-u8-set! bv 2 (bitwise-and (bitwise-arithmetic-shift-right n 8) #xff))
      (bytevector-u8-set! bv 3 (bitwise-and n #xff))
      bv))

  (define (ssh-write-string s)
    (let* ([data (cond
                   [(string? s) (string->utf8 s)]
                   [(bytevector? s) s]
                   [else (error 'ssh-write-string "expected string or bytevector" s)])]
           [len (bytevector-length data)]
           [bv (make-bytevector (+ 4 len))])
      (let ([hdr (ssh-write-uint32 len)])
        (bytevector-copy! hdr 0 bv 0 4)
        (bytevector-copy! data 0 bv 4 len)
        bv)))

  (define (ssh-write-mpint n)
    (cond
      [(= n 0)
       (ssh-write-uint32 0)]
      [(> n 0)
       (let* ([bits (bitwise-length n)]
              [bytes (quotient (+ bits 7) 8)]
              ;; Add leading zero byte if high bit set
              [need-pad (bitwise-bit-set? n (- (* bytes 8) 1))]
              [total (if need-pad (+ bytes 1) bytes)]
              [bv (make-bytevector (+ 4 total) 0)])
         (let ([hdr (ssh-write-uint32 total)])
           (bytevector-copy! hdr 0 bv 0 4))
         (let loop ([i 0] [shift (* (- bytes 1) 8)])
           (when (< i bytes)
             (bytevector-u8-set! bv (+ 4 (if need-pad 1 0) i)
               (bitwise-and (bitwise-arithmetic-shift-right n shift) #xff))
             (loop (+ i 1) (- shift 8))))
         bv)]
      [else
       (error 'ssh-write-mpint "negative mpint not supported" n)]))

  (define (ssh-write-name-list names)
    (ssh-write-string (apply string-append
      (let loop ([ns names] [acc '()])
        (cond
          [(null? ns) (reverse acc)]
          [(null? (cdr ns)) (reverse (cons (car ns) acc))]
          [else (loop (cdr ns) (cons "," (cons (car ns) acc)))])))))

  (define (ssh-write-boolean b)
    (let ([bv (make-bytevector 1)])
      (bytevector-u8-set! bv 0 (if b 1 0))
      bv))

  (define (ssh-write-byte n)
    (let ([bv (make-bytevector 1)])
      (bytevector-u8-set! bv 0 (bitwise-and n #xff))
      bv))

  ;; ---- Wire format readers ----

  (define (ssh-read-uint32 bv offset)
    (when (> (+ offset 4) (bytevector-length bv))
      (error 'ssh-read-uint32 "buffer underflow" offset))
    (let ([n (bitwise-ior
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv offset) 24)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 1)) 16)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 2)) 8)
               (bytevector-u8-ref bv (+ offset 3)))])
      (cons n (+ offset 4))))

  (define (ssh-read-string bv offset)
    (let* ([r (ssh-read-uint32 bv offset)]
           [len (car r)]
           [off (cdr r)])
      (when (> (+ off len) (bytevector-length bv))
        (error 'ssh-read-string "buffer underflow" off len))
      (let ([data (make-bytevector len)])
        (bytevector-copy! bv off data 0 len)
        (cons data (+ off len)))))

  (define (ssh-read-mpint bv offset)
    (let* ([r (ssh-read-string bv offset)]
           [data (car r)]
           [off (cdr r)]
           [len (bytevector-length data)])
      (if (= len 0)
        (cons 0 off)
        (let loop ([i 0] [n 0])
          (if (>= i len)
            (cons n off)
            (loop (+ i 1)
                  (bitwise-ior
                    (bitwise-arithmetic-shift-left n 8)
                    (bytevector-u8-ref data i))))))))

  (define (ssh-read-name-list bv offset)
    (let* ([r (ssh-read-string bv offset)]
           [data (car r)]
           [off (cdr r)]
           [s (utf8->string data)])
      (cons (if (string=? s "")
              '()
              (let split ([s s] [acc '()])
                (let ([pos (let find ([i 0])
                             (cond
                               [(>= i (string-length s)) #f]
                               [(char=? (string-ref s i) #\,) i]
                               [else (find (+ i 1))]))])
                  (if pos
                    (split (substring s (+ pos 1) (string-length s))
                           (cons (substring s 0 pos) acc))
                    (reverse (cons s acc))))))
            off)))

  (define (ssh-read-boolean bv offset)
    (when (> (+ offset 1) (bytevector-length bv))
      (error 'ssh-read-boolean "buffer underflow" offset))
    (cons (not (= (bytevector-u8-ref bv offset) 0))
          (+ offset 1)))

  (define (ssh-read-byte bv offset)
    (when (> (+ offset 1) (bytevector-length bv))
      (error 'ssh-read-byte "buffer underflow" offset))
    (cons (bytevector-u8-ref bv offset) (+ offset 1)))

  ;; ---- Packet assembly ----

  (define (ssh-make-payload msg-type . parts)
    (let* ([type-bv (ssh-write-byte msg-type)]
           [all-parts (cons type-bv parts)]
           [total (apply + (map bytevector-length all-parts))]
           [result (make-bytevector total)])
      (let loop ([parts all-parts] [off 0])
        (unless (null? parts)
          (let ([p (car parts)])
            (bytevector-copy! p 0 result off (bytevector-length p))
            (loop (cdr parts) (+ off (bytevector-length p))))))
      result))

  ) ;; end library
