#!chezscheme
;;; chez-ssh — SSH agent for Chez Scheme
;;;
;;; Implements the SSH agent protocol with Ed25519 support.
;;; Private keys are stored in mlock'd C memory and never enter
;;; the Scheme heap. Signing happens entirely in C via OpenSSL.
;;;
;;; Usage:
;;;   (import (chez-ssh))
;;;   (ssh-agent-load-key-file "~/.ssh/id_ed25519")
;;;   (ssh-agent-start)  ;; starts socket, sets SSH_AUTH_SOCK
;;;   ;; ... ssh, git, etc. now use this agent ...
;;;   (ssh-agent-stop)

(library (chez-ssh)
  (export
    ;; Key management
    ssh-agent-load-openssh-key   ;; (bv) → index or #f
    ssh-agent-load-key-file      ;; (path) → index or #f
    ssh-agent-load-ed25519-seed  ;; (seed-bv comment) → index or #f
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
    )

  (import (chezscheme))

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
          (if (eof-object? data)
            #f
            (ssh-agent-load-openssh-key data))))))

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
                  "Failed to start SSH agent")))]))

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
