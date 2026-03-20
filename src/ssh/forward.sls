#!chezscheme
;;; (ssh forward) — SSH port forwarding (RFC 4254 §7)
;;;
;;; Local (-L) and remote (-R) port forwarding.

(library (ssh forward)
  (export
    ;; Forward listener record
    make-forward-listener
    forward-listener?
    forward-listener-local-port
    forward-listener-remote-host
    forward-listener-remote-port

    ;; Local forwarding
    ssh-forward-local-start    ;; (ts table bind-addr local-port remote-host remote-port) → listener
    ssh-forward-local-stop     ;; (listener) → void

    ;; Remote forwarding
    ssh-forward-remote-request ;; (ts bind-addr remote-port) → allocated-port
    ssh-forward-remote-cancel  ;; (ts bind-addr remote-port) → void
    )

  (import (chezscheme) (ssh wire) (ssh transport) (ssh channel))

  ;; ---- FFI ----
  (define c-tcp-listen
    (foreign-procedure "chez_ssh_tcp_listen" (string int) int))
  (define c-tcp-accept
    (foreign-procedure "chez_ssh_tcp_accept" (int) int))
  (define c-tcp-read
    (foreign-procedure "chez_ssh_tcp_read" (int u8* int) int))
  (define c-tcp-write
    (foreign-procedure "chez_ssh_tcp_write" (int u8* int) int))
  (define c-tcp-close
    (foreign-procedure "chez_ssh_tcp_close" (int) int))

  ;; ---- Forward listener record ----

  (define-record-type forward-listener
    (fields
      local-port      ;; int
      remote-host     ;; string
      remote-port     ;; int
      listen-fd       ;; int (listening socket)
      (mutable thread)     ;; thread or #f
      (mutable running?))  ;; boolean
    (protocol
      (lambda (new)
        (lambda (local-port remote-host remote-port listen-fd)
          (new local-port remote-host remote-port listen-fd #f #t)))))

  ;; ---- Local forwarding ----

  (define (ssh-forward-local-start ts table bind-addr local-port remote-host remote-port)
    (let ([listen-fd (c-tcp-listen (or bind-addr "127.0.0.1") local-port)])
      (when (< listen-fd 0)
        (error 'ssh-forward-local-start "failed to listen" bind-addr local-port))
      (let ([listener (make-forward-listener local-port remote-host remote-port listen-fd)])
        ;; Start accept loop in a new thread
        (forward-listener-thread-set! listener
          (fork-thread
            (lambda ()
              (local-forward-accept-loop ts table listener))))
        listener)))

  (define (local-forward-accept-loop ts table listener)
    (let loop ()
      (when (forward-listener-running? listener)
        (let ([client-fd (c-tcp-accept (forward-listener-listen-fd listener))])
          (when (>= client-fd 0)
            ;; Open a direct-tcpip channel for this connection
            (guard (e [#t (c-tcp-close client-fd)])
              (let ([ch (ssh-channel-open-direct-tcpip ts table
                          (forward-listener-remote-host listener)
                          (forward-listener-remote-port listener)
                          "127.0.0.1" 0)])
                ;; Relay data between client-fd and SSH channel
                (fork-thread
                  (lambda ()
                    (forward-relay ts table ch client-fd))))))
          (loop)))))

  (define (forward-relay ts table ch client-fd)
    ;; Bidirectional relay between a local TCP socket and an SSH channel
    ;; Simplified: read from channel, write to fd; read from fd, write to channel
    ;; In a real implementation, we'd use select/poll. Here we use two threads.

    ;; Thread 1: channel → fd
    (let ([ch->fd-thread
           (fork-thread
             (lambda ()
               (let loop ()
                 (let ([data (ssh-channel-read ts table ch)])
                   (when data
                     (let ([rc (c-tcp-write client-fd data (bytevector-length data))])
                       (when (> rc 0) (loop))))))))])

      ;; Thread 2 (this thread): fd → channel
      (let loop ()
        (let* ([buf (make-bytevector 32768)]
               [n (c-tcp-read client-fd buf 32768)])
          (when (> n 0)
            (let ([data (make-bytevector n)])
              (bytevector-copy! buf 0 data 0 n)
              (ssh-channel-send-data ts ch data)
              (loop)))))

      ;; Cleanup
      (ssh-channel-send-eof ts ch)
      (ssh-channel-close ts ch)
      (c-tcp-close client-fd)))

  (define (ssh-forward-local-stop listener)
    (forward-listener-running?-set! listener #f)
    (c-tcp-close (forward-listener-listen-fd listener)))

  ;; ---- Remote forwarding ----

  (define (ssh-forward-remote-request ts bind-addr remote-port)
    ;; Send global request for tcpip-forward
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_GLOBAL_REQUEST
        (ssh-write-string "tcpip-forward")
        (ssh-write-boolean #t)  ;; want reply
        (ssh-write-string (or bind-addr ""))
        (ssh-write-uint32 remote-port)))
    ;; Wait for reply
    (let ([reply (ssh-transport-recv-packet ts)])
      (case (bytevector-u8-ref reply 0)
        [(81)  ;; SSH_MSG_REQUEST_SUCCESS
         (if (= remote-port 0)
           ;; Server allocated a port — read it
           (let ([r (ssh-read-uint32 reply 1)])
             (car r))
           remote-port)]
        [(82)  ;; SSH_MSG_REQUEST_FAILURE
         (error 'ssh-forward-remote-request "server rejected forwarding request")]
        [else
         (error 'ssh-forward-remote-request "unexpected response"
                (bytevector-u8-ref reply 0))])))

  (define (ssh-forward-remote-cancel ts bind-addr remote-port)
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_GLOBAL_REQUEST
        (ssh-write-string "cancel-tcpip-forward")
        (ssh-write-boolean #t)
        (ssh-write-string (or bind-addr ""))
        (ssh-write-uint32 remote-port)))
    (let ([reply (ssh-transport-recv-packet ts)])
      (unless (= (bytevector-u8-ref reply 0) 81)
        (error 'ssh-forward-remote-cancel "cancel failed"))))

  ) ;; end library
