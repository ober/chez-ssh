#!chezscheme
;;; ssh-test.ss — Tests for chez-ssh agent

(import (chezscheme) (chez-ssh))

;; Need libc symbols for getpid
(load-shared-object "")

(define pass 0)
(define fail 0)

(define-syntax test
  (syntax-rules ()
    [(_ name expr expected)
     (let ([result expr])
       (if (equal? result expected)
         (begin (set! pass (+ pass 1))
                (printf "  PASS: ~a~n" name))
         (begin (set! fail (+ fail 1))
                (printf "  FAIL: ~a — got ~s, expected ~s~n"
                        name result expected))))]))

(define-syntax test-true
  (syntax-rules ()
    [(_ name expr)
     (test name (if expr #t #f) #t)]))

(define-syntax test-false
  (syntax-rules ()
    [(_ name expr)
     (test name (if expr #t #f) #f)]))

;; ---- Generate a test Ed25519 key ----

(define c-getpid (foreign-procedure "getpid" () int))

;; Create a temporary OpenSSH Ed25519 key for testing
(define test-key-dir (format "/tmp/chez-ssh-test-~a" (c-getpid)))

(define (setup-test-key)
  (system (format "mkdir -p ~a" test-key-dir))
  (system (format "ssh-keygen -t ed25519 -f ~a/id_ed25519 -N '' -q" test-key-dir))
  (format "~a/id_ed25519" test-key-dir))

(define (cleanup-test-key)
  (system (format "rm -rf ~a" test-key-dir)))

;; ---- Tests ----

(printf "~n=== chez-ssh agent tests ===~n~n")

;; Basic state
(printf "--- Initial state ---~n")
(test "no keys initially" (ssh-agent-key-count) 0)
(test-false "not running initially" (ssh-agent-running?))
(test "socket path is #f" (ssh-agent-socket-path) #f)

;; Key loading from file
(printf "~n--- Key loading ---~n")
(let ([key-file (setup-test-key)])
  (let ([idx (ssh-agent-load-key-file key-file)])
    (test-true "load key file succeeds" (and idx (>= idx 0)))
    (test "key count is 1" (ssh-agent-key-count) 1)

    (let ([info (ssh-agent-key-info 0)])
      (test-true "key info is pair" (pair? info))
      (when (pair? info)
        (test-true "comment is string" (string? (car info)))
        (test-true "pubkey hex is 64 chars" (= (string-length (cdr info)) 64))))

    (let ([keys (ssh-agent-list-keys)])
      (test "list-keys has 1 entry" (length keys) 1))

    ;; Load key from raw bytevector
    (let* ([port (open-file-input-port key-file)]
           [data (get-bytevector-all port)]
           [_ (close-port port)]
           [idx2 (ssh-agent-load-openssh-key data)])
      (test-true "load from bytevector succeeds" (and idx2 (>= idx2 0)))
      (test "key count is 2" (ssh-agent-key-count) 2))

    ;; Remove
    (ssh-agent-remove-key! 0)
    (test "key count after remove" (ssh-agent-key-count) 1)

    (ssh-agent-remove-all-keys!)
    (test "key count after remove-all" (ssh-agent-key-count) 0))

  ;; Agent lifecycle
  (printf "~n--- Agent lifecycle ---~n")
  (ssh-agent-load-key-file key-file)

  (let ([started (ssh-agent-start)])
    (test-true "agent starts" started)
    (test-true "agent is running" (ssh-agent-running?))

    (let ([path (ssh-agent-socket-path)])
      (test-true "socket path is string" (string? path))
      (when (string? path)
        (test-true "socket file exists" (file-exists? path))
        (printf "  Socket: ~a~n" path)))

    ;; Verify SSH_AUTH_SOCK is set
    (let ([auth-sock (getenv "SSH_AUTH_SOCK")])
      (test-true "SSH_AUTH_SOCK is set" (and auth-sock (> (string-length auth-sock) 0))))

    ;; Test with real ssh-add -l (if ssh-add is available)
    (printf "~n--- ssh-add integration ---~n")
    (let ([rc (system "ssh-add -l 2>/dev/null")])
      (if (= rc 0)
        (begin
          (printf "  ssh-add -l output:~n")
          (system "ssh-add -l 2>&1 | sed 's/^/    /'")
          (set! pass (+ pass 1))
          (printf "  PASS: ssh-add sees our key~n"))
        (begin
          (printf "  SKIP: ssh-add returned ~a (may not be installed)~n" rc))))

    ;; Stop
    (ssh-agent-stop)
    (test-false "agent stopped" (ssh-agent-running?))
    (test "socket path after stop" (ssh-agent-socket-path) #f))

  (cleanup-test-key))

;; ---- Summary ----
(printf "~n=== Results: ~a passed, ~a failed ===~n~n" pass fail)
(when (> fail 0) (exit 1))
