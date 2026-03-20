#!chezscheme
;;; (ssh session) — SSH session channels (RFC 4254 §6)
;;;
;;; Exec, shell/PTY, and subsystem requests on session channels.

(library (ssh session)
  (export
    ssh-session-exec           ;; (ts table command) → channel
    ssh-session-shell          ;; (ts table) → channel
    ssh-session-request-pty    ;; (ts table channel #:term #:cols #:rows) → void
    ssh-session-subsystem      ;; (ts table channel subsystem-name) → void
    ssh-session-exec-simple    ;; (ts table command) → (exit-status . output-string)
    )

  (import (chezscheme) (ssh wire) (ssh transport) (ssh channel))

  ;; ---- Exec ----

  (define (ssh-session-exec ts table command)
    (let ([ch (ssh-channel-open-session ts table)])
      ;; Send exec request
      (ssh-transport-send-packet ts
        (ssh-make-payload SSH_MSG_CHANNEL_REQUEST
          (ssh-write-uint32 (ssh-channel-remote-id ch))
          (ssh-write-string "exec")
          (ssh-write-boolean #t)  ;; want reply
          (ssh-write-string command)))
      ;; Wait for success/failure
      (ssh-channel-dispatch-until ts table
        (lambda ()
          ;; Either we got channel success or the channel was closed
          ;; We dispatch until we see the reply
          ;; The dispatch loop handles CHANNEL_SUCCESS/FAILURE
          ;; For exec, just return the channel — the caller reads from it
          #t))
      ch))

  ;; ---- Shell ----

  (define (ssh-session-shell ts table)
    (let ([ch (ssh-channel-open-session ts table)])
      ;; Request PTY first
      (ssh-session-request-pty ts table ch)
      ;; Request shell
      (ssh-transport-send-packet ts
        (ssh-make-payload SSH_MSG_CHANNEL_REQUEST
          (ssh-write-uint32 (ssh-channel-remote-id ch))
          (ssh-write-string "shell")
          (ssh-write-boolean #t)))
      ch))

  ;; ---- PTY request ----

  (define ssh-session-request-pty
    (case-lambda
      [(ts table ch) (ssh-session-request-pty ts table ch "xterm" 80 24)]
      [(ts table ch term cols rows)
       (let ([modes (make-bytevector 1 0)])  ;; empty terminal modes (TTY_OP_END)
         (ssh-transport-send-packet ts
           (ssh-make-payload SSH_MSG_CHANNEL_REQUEST
             (ssh-write-uint32 (ssh-channel-remote-id ch))
             (ssh-write-string "pty-req")
             (ssh-write-boolean #t)   ;; want reply
             (ssh-write-string term)
             (ssh-write-uint32 cols)
             (ssh-write-uint32 rows)
             (ssh-write-uint32 0)     ;; pixel width
             (ssh-write-uint32 0)     ;; pixel height
             (ssh-write-string modes))))]))

  ;; ---- Subsystem ----

  (define (ssh-session-subsystem ts table ch subsystem-name)
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_CHANNEL_REQUEST
        (ssh-write-uint32 (ssh-channel-remote-id ch))
        (ssh-write-string "subsystem")
        (ssh-write-boolean #t)
        (ssh-write-string subsystem-name))))

  ;; ---- Simple exec (convenience) ----

  (define (ssh-session-exec-simple ts table command)
    ;; Execute command, collect all stdout, return (exit-status . output)
    (let ([ch (ssh-session-exec ts table command)])
      (let loop ([chunks '()])
        (let ([data (ssh-channel-read ts table ch)])
          (if data
            (loop (cons data chunks))
            ;; EOF — drain remaining dispatches to get exit status
            (begin
              (let drain ()
                (unless (ssh-channel-closed? ch)
                  (ssh-channel-dispatch ts table)
                  (drain)))
              (ssh-channel-close ts ch)
              (let* ([all-data (apply bytevector-append (reverse chunks))]
                     [output (utf8->string all-data)]
                     [status (or (ssh-channel-exit-status ch) -1)])
                (cons status output))))))))

  ;; ---- Helper ----

  (define (bytevector-append . bvs)
    (let* ([total (apply + (map bytevector-length bvs))]
           [result (make-bytevector total)])
      (let loop ([bvs bvs] [off 0])
        (unless (null? bvs)
          (let ([bv (car bvs)])
            (bytevector-copy! bv 0 result off (bytevector-length bv))
            (loop (cdr bvs) (+ off (bytevector-length bv))))))
      result))

  ) ;; end library
