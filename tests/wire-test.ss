#!/usr/bin/env scheme-script
#!chezscheme

;;; Wire format tests for (ssh wire)
;;; Tests SSH binary encoding/decoding per RFC 4251

(import (chezscheme) (ssh wire))

;; ---- Test infrastructure ----
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

(define-syntax test-bv
  (syntax-rules ()
    [(_ name expected actual)
     (let ([e expected] [a actual])
       (if (bytevector=? e a)
         (begin (set! pass-count (+ pass-count 1))
                (printf "  PASS: ~a~n" name))
         (begin (set! fail-count (+ fail-count 1))
                (printf "  FAIL: ~a~n    expected: ~s~n    actual:   ~s~n" name e a))))]))

;; ---- uint32 tests ----
(printf "~n=== uint32 ===~n")

(test-bv "write uint32 0"
  #vu8(0 0 0 0)
  (ssh-write-uint32 0))

(test-bv "write uint32 1"
  #vu8(0 0 0 1)
  (ssh-write-uint32 1))

(test-bv "write uint32 256"
  #vu8(0 0 1 0)
  (ssh-write-uint32 256))

(test-bv "write uint32 #xDEADBEEF"
  #vu8(#xDE #xAD #xBE #xEF)
  (ssh-write-uint32 #xDEADBEEF))

(let ([r (ssh-read-uint32 #vu8(0 0 0 42) 0)])
  (test "read uint32 42" 42 (car r))
  (test "read uint32 offset" 4 (cdr r)))

(let ([r (ssh-read-uint32 #vu8(#xFF #xFF #xFF #xFF) 0)])
  (test "read uint32 max" #xFFFFFFFF (car r)))

;; ---- string tests ----
(printf "~n=== string ===~n")

(test-bv "write string hello"
  #vu8(0 0 0 5 104 101 108 108 111)
  (ssh-write-string "hello"))

(test-bv "write empty string"
  #vu8(0 0 0 0)
  (ssh-write-string ""))

(test-bv "write bytevector as string"
  #vu8(0 0 0 3 1 2 3)
  (ssh-write-string #vu8(1 2 3)))

(let ([r (ssh-read-string #vu8(0 0 0 5 104 101 108 108 111) 0)])
  (test-bv "read string hello" #vu8(104 101 108 108 111) (car r))
  (test "read string offset" 9 (cdr r)))

;; ---- mpint tests (RFC 4251 §5) ----
(printf "~n=== mpint ===~n")

(test-bv "write mpint 0"
  #vu8(0 0 0 0)
  (ssh-write-mpint 0))

(test-bv "write mpint 1"
  #vu8(0 0 0 1 1)
  (ssh-write-mpint 1))

(test-bv "write mpint #x80 (needs leading zero)"
  #vu8(0 0 0 2 0 #x80)
  (ssh-write-mpint #x80))

(test-bv "write mpint #x7F"
  #vu8(0 0 0 1 #x7F)
  (ssh-write-mpint #x7F))

(test-bv "write mpint #x0102"
  #vu8(0 0 0 2 1 2)
  (ssh-write-mpint #x0102))

(let ([r (ssh-read-mpint #vu8(0 0 0 0) 0)])
  (test "read mpint 0" 0 (car r)))

(let ([r (ssh-read-mpint #vu8(0 0 0 1 42) 0)])
  (test "read mpint 42" 42 (car r)))

(let ([r (ssh-read-mpint #vu8(0 0 0 2 0 #x80) 0)])
  (test "read mpint 128" 128 (car r)))

;; ---- name-list tests ----
(printf "~n=== name-list ===~n")

(test-bv "write name-list single"
  (ssh-write-string "foo")
  (ssh-write-name-list '("foo")))

(test-bv "write name-list multiple"
  (ssh-write-string "foo,bar,baz")
  (ssh-write-name-list '("foo" "bar" "baz")))

(test-bv "write name-list empty"
  (ssh-write-string "")
  (ssh-write-name-list '()))

(let ([r (ssh-read-name-list (ssh-write-name-list '("a" "b" "c")) 0)])
  (test "read name-list" '("a" "b" "c") (car r)))

(let ([r (ssh-read-name-list (ssh-write-name-list '()) 0)])
  (test "read empty name-list" '() (car r)))

;; ---- boolean tests ----
(printf "~n=== boolean ===~n")

(test-bv "write boolean true"
  #vu8(1)
  (ssh-write-boolean #t))

(test-bv "write boolean false"
  #vu8(0)
  (ssh-write-boolean #f))

(let ([r (ssh-read-boolean #vu8(1) 0)])
  (test "read boolean true" #t (car r)))

(let ([r (ssh-read-boolean #vu8(0) 0)])
  (test "read boolean false" #f (car r)))

;; ---- byte tests ----
(printf "~n=== byte ===~n")

(test-bv "write byte 42"
  #vu8(42)
  (ssh-write-byte 42))

(let ([r (ssh-read-byte #vu8(255) 0)])
  (test "read byte 255" 255 (car r)))

;; ---- payload assembly ----
(printf "~n=== payload ===~n")

(let ([p (ssh-make-payload 20  ;; SSH_MSG_KEXINIT
           (ssh-write-string "test"))])
  (test "payload msg type" 20 (bytevector-u8-ref p 0))
  (test "payload length" (+ 1 4 4) (bytevector-length p)))

;; ---- message constants ----
(printf "~n=== constants ===~n")

(test "KEXINIT" 20 SSH_MSG_KEXINIT)
(test "NEWKEYS" 21 SSH_MSG_NEWKEYS)
(test "USERAUTH_REQUEST" 50 SSH_MSG_USERAUTH_REQUEST)
(test "CHANNEL_DATA" 94 SSH_MSG_CHANNEL_DATA)
(test "DISCONNECT" 1 SSH_MSG_DISCONNECT)

;; ---- roundtrip tests ----
(printf "~n=== roundtrip ===~n")

;; uint32 roundtrip
(let* ([val #xCAFEBABE]
       [bv (ssh-write-uint32 val)]
       [r (ssh-read-uint32 bv 0)])
  (test "uint32 roundtrip" val (car r)))

;; string roundtrip
(let* ([val "SSH-2.0-chez-ssh_1.0"]
       [bv (ssh-write-string val)]
       [r (ssh-read-string bv 0)])
  (test "string roundtrip" val (utf8->string (car r))))

;; name-list roundtrip
(let* ([val '("curve25519-sha256" "aes256-ctr" "hmac-sha2-256")]
       [bv (ssh-write-name-list val)]
       [r (ssh-read-name-list bv 0)])
  (test "name-list roundtrip" val (car r)))

;; ---- Summary ----
(printf "~n=== Results ===~n")
(printf "~a passed, ~a failed~n" pass-count fail-count)
(when (> fail-count 0)
  (exit 1))
