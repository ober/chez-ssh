#!chezscheme
;;; chez-ssh — SSH agent + client for Chez Scheme
;;;
;;; Implements the SSH agent protocol with Ed25519 support,
;;; plus a full SSH client (connect, exec, SFTP, port forwarding).
;;;
;;; Agent usage:
;;;   (import (chez-ssh))
;;;   (ssh-agent-load-key-file "~/.ssh/id_ed25519")
;;;   (ssh-agent-start)
;;;   (ssh-agent-stop)
;;;
;;; Client usage:
;;;   (import (chez-ssh))
;;;   (let ([conn (ssh-connect "example.com" 22 "user" "~/.ssh/id_ed25519")])
;;;     (ssh-run conn "uname -a")  ;; → (0 . "Linux ...")
;;;     (ssh-disconnect conn))

(library (chez-ssh)
  (export
    ;; Key management (agent)
    ssh-agent-load-openssh-key   ;; (bv) → index or #f
    ssh-agent-load-key-data      ;; (bv label) → index or #f (handles encrypted, prompts on /dev/tty)
    ssh-agent-load-key-file      ;; (path) → index or #f (auto-prompts for encrypted keys)
    ssh-agent-load-ed25519-seed  ;; (seed-bv comment) → index or #f
    ssh-key-encrypted?           ;; (bv) → #t / #f
    ssh-agent-key-count          ;; () → int
    ssh-agent-key-info           ;; (index) → (comment . pubkey-hex) or #f
    ssh-agent-list-keys          ;; () → list of (index comment pubkey-hex)
    ssh-agent-remove-key!        ;; (index) → void
    ssh-agent-remove-all-keys!   ;; () → void

    ;; Agent lifecycle
    ssh-agent-start              ;; (#:dir dir) → #t or error
    ssh-agent-stop               ;; () → void
    ssh-agent-running?           ;; () → boolean
    ssh-agent-socket-path        ;; () → string or #f

    ;; SSH client — connection
    ssh-connect                  ;; (host #:port #:user #:key-file #:password) → connection
    ssh-disconnect               ;; (conn) → void
    ssh-connection?

    ;; SSH client — command execution
    ssh-run                      ;; (conn command) → (exit-status . output)
    ssh-capture                  ;; (conn command) → output-string

    ;; SSH client — channels
    ssh-exec                     ;; (conn command) → channel
    ssh-shell                    ;; (conn) → channel

    ;; SSH client — SFTP
    ssh-sftp                     ;; (conn) → sftp-session
    ssh-sftp-close               ;; (conn sftp) → void
    ssh-scp-get                  ;; (conn remote local) → void
    ssh-scp-put                  ;; (conn local remote) → void

    ;; SSH client — port forwarding
    ssh-forward-local            ;; (conn local-port remote-host remote-port) → listener
    ssh-forward-remote           ;; (conn remote-port) → allocated-port
    )

  (import (chezscheme)
          (ssh client))

  ;; Load the shared library
  (define _shim
    (guard (e [#t (void)])
      (load-shared-object "chez_ssh_shim.so")))

  (define _shim-local
    (guard (e [#t (void)])
      (cond
        [(file-exists? "./chez_ssh_shim.so")
         (load-shared-object "./chez_ssh_shim.so")]
        [else (void)])))

  ;; Use Chez's putenv for environment — ensures both Chez's getenv
  ;; and child process environ see the change.
  ;; POSIX setenv alone doesn't update Chez's cached env.

  ;; ---- FFI bindings ----

  (define c-load-openssh-key
    (foreign-procedure "chez_ssh_agent_load_openssh_key" (u8* int) int))

  (define c-key-is-encrypted
    (foreign-procedure "chez_ssh_key_is_encrypted" (u8* int) int))

  (define c-load-key-with-pass
    (foreign-procedure "chez_ssh_agent_load_openssh_key_with_pass" (u8* int string int) int))

  (define c-load-key-prompted
    (foreign-procedure "chez_ssh_agent_load_key_prompted" (u8* int string) int))

  (define c-load-ed25519
    (foreign-procedure "chez_ssh_agent_load_ed25519" (u8* string) int))

  (define c-key-count
    (foreign-procedure "chez_ssh_agent_key_count" () int))

  (define c-get-pubkey-blob
    (foreign-procedure "chez_ssh_agent_get_pubkey_blob" (int u8* int) int))

  (define c-get-comment
    (foreign-procedure "chez_ssh_agent_get_comment" (int u8* int) int))

  (define c-remove-key
    (foreign-procedure "chez_ssh_agent_remove_key" (int) void))

  (define c-remove-all
    (foreign-procedure "chez_ssh_agent_remove_all" () void))

  (define c-start
    (foreign-procedure "chez_ssh_agent_start" (string) int))

  (define c-get-socket-path
    (foreign-procedure "chez_ssh_agent_get_socket_path" () string))
  (define c-get-agent-dir
    (foreign-procedure "chez_ssh_agent_get_dir" () string))

  (define c-is-running
    (foreign-procedure "chez_ssh_agent_is_running" () int))

  (define c-stop
    (foreign-procedure "chez_ssh_agent_stop" () void))

  ;; ---- Helpers ----

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

  ;; Extract the raw 32-byte pubkey from a 51-byte SSH blob
  ;; Blob format: string("ssh-ed25519") || string(pubkey_32)
  ;; = uint32(11) "ssh-ed25519" uint32(32) <32 bytes>
  ;; Pubkey starts at offset 4+11+4 = 19
  (define (blob->pubkey-hex blob bloblen)
    (if (< bloblen 51)
      ""
      (let ([pk (make-bytevector 32)])
        (bytevector-copy! blob 19 pk 0 32)
        (bytes->hex pk))))

  ;; ---- Key management ----

  (define (ssh-agent-load-openssh-key data)
    (let ([bv (if (string? data) (string->utf8 data) data)])
      (let ([idx (c-load-openssh-key bv (bytevector-length bv))])
        (if (>= idx 0) idx #f))))

  (define (ssh-key-encrypted? data)
    (let ([bv (if (string? data) (string->utf8 data) data)])
      (= (c-key-is-encrypted bv (bytevector-length bv)) 1)))

  ;; Load key from raw data (bytevector or string), prompts for passphrase if encrypted
  (define (ssh-agent-load-key-data data label)
    (let ([bv (if (string? data) (string->utf8 data) data)])
      (cond
        [(= (c-key-is-encrypted bv (bytevector-length bv)) 1)
         (let ([idx (c-load-key-prompted
                      bv (bytevector-length bv)
                      (string-append "Enter passphrase for " (or label "key") ": "))])
           (if (>= idx 0) idx #f))]
        [else
         (let ([idx (c-load-openssh-key bv (bytevector-length bv))])
           (if (>= idx 0) idx #f))])))

  (define (ssh-agent-load-key-file path)
    (let ([expanded (if (and (> (string-length path) 0)
                             (char=? (string-ref path 0) #\~))
                      (string-append (or (getenv "HOME") "")
                                     (substring path 1 (string-length path)))
                      path)])
      (guard (e [#t #f])
        (let* ([port (open-file-input-port expanded)]
               [data (get-bytevector-all port)])
          (close-port port)
          (cond
            [(eof-object? data) #f]
            [(= (c-key-is-encrypted data (bytevector-length data)) 1)
             ;; Encrypted key — prompt for passphrase on /dev/tty
             (let ([idx (c-load-key-prompted
                          data (bytevector-length data)
                          (string-append "Enter passphrase for " path ": "))])
               (if (>= idx 0) idx #f))]
            [else
             (ssh-agent-load-openssh-key data)])))))

  (define (ssh-agent-load-ed25519-seed seed comment)
    (let ([idx (c-load-ed25519 seed (or comment ""))])
      (if (>= idx 0) idx #f)))

  (define (ssh-agent-key-count)
    (c-key-count))

  (define (ssh-agent-key-info index)
    (let ([comment-buf (make-bytevector 256 0)]
          [blob-buf (make-bytevector 51 0)])
      (let ([clen (c-get-comment index comment-buf 256)]
            [blen (c-get-pubkey-blob index blob-buf 51)])
        (if (or (< clen 0) (< blen 0))
          #f
          (let ([comment (utf8->string
                           (let ([r (make-bytevector clen)])
                             (bytevector-copy! comment-buf 0 r 0 clen)
                             r))]
                [hex (blob->pubkey-hex blob-buf blen)])
            (cons comment hex))))))

  (define (ssh-agent-list-keys)
    (let loop ([i 0] [acc '()])
      (if (>= i (ssh-agent-key-count))
        (reverse acc)
        (let ([info (ssh-agent-key-info i)])
          (loop (+ i 1)
                (if info
                  (cons (list i (car info) (cdr info)) acc)
                  acc))))))

  (define (ssh-agent-remove-key! index)
    (c-remove-key index))

  (define (ssh-agent-remove-all-keys!)
    (c-remove-all))

  ;; ---- Agent lifecycle ----

  (define ssh-agent-start
    (case-lambda
      [() (ssh-agent-start "")]
      [(dir)
       (let ([rc (c-start (or dir ""))])
         (if (= rc 0)
           (begin
             ;; Set SSH_AUTH_SOCK for child processes
             (let ([path (c-get-socket-path)])
               (when (and path (not (string=? path "")))
                 (putenv "SSH_AUTH_SOCK" path)))
             #t)
           (error 'ssh-agent-start
                  (string-append "Failed to start SSH agent ("
                    (case rc
                      [(-1) (string-append "mkdir failed: " (or (c-get-agent-dir) "?"))]
                      [(-2) "socket() failed"]
                      [(-3) (string-append "bind() failed: " (or (c-get-agent-dir) "?"))]
                      [(-4) "listen() failed"]
                      [(-5) "pipe() failed"]
                      [(-6) "pthread_create() failed"]
                      [else (string-append "error code " (number->string rc))])
                    ")"))))]))

  (define (ssh-agent-stop)
    (c-stop)
    ;; Clear SSH_AUTH_SOCK
    (putenv "SSH_AUTH_SOCK" ""))

  (define (ssh-agent-running?)
    (= (c-is-running) 1))

  (define (ssh-agent-socket-path)
    (and (ssh-agent-running?)
         (c-get-socket-path)))

  ) ;; end library
