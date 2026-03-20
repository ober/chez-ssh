#!chezscheme
;;; Integration test for SSH client
;;; Requires: localhost sshd with key-based auth (~/.ssh/id_ed25519)

(import (chezscheme)
        (ssh wire)
        (ssh transport)
        (ssh kex)
        (ssh known-hosts)
        (ssh auth)
        (ssh channel)
        (ssh session)
        (ssh client))

(load-shared-object "./chez_ssh_crypto.so")

;; ---- Helpers ----

(define passed 0)
(define failed 0)

(define-syntax test
  (syntax-rules ()
    [(_ name expr)
     (guard (e [#t (set! failed (+ failed 1))
                   (display (string-append "  FAIL: " name "\n"))
                   (display (string-append "    Error: "
                              (if (message-condition? e)
                                (condition-message e)
                                (format "~a" e))
                              "\n"))])
       (let ([result expr])
         (if result
           (begin (set! passed (+ passed 1))
                  (display (string-append "  PASS: " name "\n")))
           (begin (set! failed (+ failed 1))
                  (display (string-append "  FAIL: " name " (returned #f)\n"))))))]))

(define (string-prefix? prefix str)
  (and (>= (string-length str) (string-length prefix))
       (string=? (substring str 0 (string-length prefix)) prefix)))

(define (string-contains haystack needle)
  (let ([hlen (string-length haystack)]
        [nlen (string-length needle)])
    (let loop ([i 0])
      (cond
        [(> (+ i nlen) hlen) #f]
        [(string=? (substring haystack i (+ i nlen)) needle) #t]
        [else (loop (+ i 1))]))))

;;; ---- Transport-level tests ----

(display "\n=== Transport Layer ===\n")

;; Test TCP connect
(let ([fd (ssh-transport-connect "127.0.0.1" 22)])
  (test "tcp connect" (and (integer? fd) (> fd 0)))

  ;; Test version exchange
  (let ([client-ver (ssh-transport-send-version fd)])
    (test "send version" (string? client-ver))
    (test "version starts with SSH-2.0" (string-prefix? "SSH-2.0-" client-ver))

    (let ([server-ver (ssh-transport-recv-version fd)])
      (test "recv version" (string? server-ver))
      (test "server version starts with SSH-2.0" (string-prefix? "SSH-2.0-" server-ver))

      ;; Create transport state
      (let ([ts (make-transport-state fd server-ver client-ver)])
        (test "transport state" (transport-state? ts))

        ;; Key exchange (accept any host key for testing)
        (test "kex perform"
          (let ([H (ssh-kex-perform ts (lambda (host-key-blob) #t))])
            (and (bytevector? H) (= (bytevector-length H) 32))))

        ;; Check session ID was set
        (test "session id set"
          (let ([sid (transport-state-session-id ts)])
            (and (bytevector? sid) (= (bytevector-length sid) 32))))

        ;; Check encryption is active
        (test "send cipher active"
          (cipher-state? (transport-state-send-cipher ts)))
        (test "recv cipher active"
          (cipher-state? (transport-state-recv-cipher ts)))

        ;; Test encrypted packet exchange - request userauth service
        (test "userauth service request"
          (begin
            (ssh-userauth-request ts)
            #t))

        ;; Close this connection
        (ssh-transport-close ts)
        (test "transport closed" #t)))))

;;; ---- High-level client tests ----

(display "\n=== SSH Client ===\n")

(let ([key-file (string-append (or (getenv "HOME") "") "/.ssh/id_ed25519")])
  (if (file-exists? key-file)
    (begin
      ;; Connect using the high-level API (accept any host key)
      (let ([conn (ssh-connect "127.0.0.1" 22 (or (getenv "USER") "root")
                               key-file #f)])
        (test "ssh-connect" (ssh-connection? conn))

        ;; Run a simple command
        (let ([result (ssh-run conn "echo hello")])
          (test "ssh-run returns pair" (pair? result))
          (test "ssh-run exit status 0" (= (car result) 0))
          (test "ssh-run output" (string-contains (cdr result) "hello")))

        ;; Run another command
        (let ([result (ssh-run conn "uname -s")])
          (test "uname exit status 0" (= (car result) 0))
          (test "uname output" (> (string-length (cdr result)) 0)))

        ;; Test ssh-capture
        (let ([output (ssh-capture conn "hostname")])
          (test "ssh-capture" (> (string-length output) 0)))

        ;; Test command with non-zero exit
        (let ([result (ssh-run conn "exit 42")])
          (test "non-zero exit" (= (car result) 42)))

        ;; Disconnect
        (ssh-disconnect conn)
        (test "ssh-disconnect" #t)))
    (begin
      (display "  SKIP: no ~/.ssh/id_ed25519 found, skipping client tests\n"))))

;;; ---- Results ----

(display (string-append "\n=== Results: "
                        (number->string passed) " passed, "
                        (number->string failed) " failed ===\n"))

(when (> failed 0)
  (exit 1))
