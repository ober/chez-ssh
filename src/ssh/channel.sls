#!chezscheme
;;; (ssh channel) — SSH channel multiplexing (RFC 4254)
;;;
;;; Channel open/close, data transfer, window management,
;;; and packet dispatch loop.

(library (ssh channel)
  (export
    ;; Channel record
    make-ssh-channel
    ssh-channel?
    ssh-channel-local-id
    ssh-channel-remote-id
    ssh-channel-remote-id-set!
    ssh-channel-local-window
    ssh-channel-local-window-set!
    ssh-channel-remote-window
    ssh-channel-remote-window-set!
    ssh-channel-remote-max-packet
    ssh-channel-remote-max-packet-set!
    ssh-channel-data-queue
    ssh-channel-data-queue-set!
    ssh-channel-stderr-queue
    ssh-channel-stderr-queue-set!
    ssh-channel-eof?
    ssh-channel-eof?-set!
    ssh-channel-closed?
    ssh-channel-closed?-set!
    ssh-channel-exit-status
    ssh-channel-exit-status-set!
    ssh-channel-exit-signal
    ssh-channel-exit-signal-set!

    ;; Channel table (transport-level)
    make-channel-table
    channel-table-get
    channel-table-put!
    channel-table-remove!
    channel-table-next-id
    channel-table-alloc-id

    ;; Channel operations
    ssh-channel-open-session   ;; (ts table) → channel
    ssh-channel-open-direct-tcpip ;; (ts table host port orig-host orig-port) → channel
    ssh-channel-send-data      ;; (ts channel data) → void
    ssh-channel-send-eof       ;; (ts channel) → void
    ssh-channel-close           ;; (ts channel) → void
    ssh-channel-read            ;; (ts table channel) → bytevector or #f (eof)
    ssh-channel-read-stderr     ;; (ts table channel) → bytevector or #f

    ;; Dispatch
    ssh-channel-dispatch        ;; (ts table) → process one incoming packet
    ssh-channel-dispatch-until  ;; (ts table pred) → loop until pred returns true
    )

  (import (chezscheme) (ssh wire) (ssh transport))

  ;; ---- Constants ----
  (define INITIAL-WINDOW-SIZE (* 2 1024 1024))   ;; 2 MB
  (define MAX-PACKET-SIZE 32768)                  ;; 32 KB

  ;; ---- Channel record ----

  (define-record-type ssh-channel
    (fields
      local-id                          ;; uint32
      (mutable remote-id)               ;; uint32 or #f (set on confirmation)
      (mutable local-window)            ;; bytes remaining in our window
      (mutable remote-window)           ;; bytes remaining in remote window
      (mutable remote-max-packet)       ;; max packet size for remote
      (mutable data-queue)              ;; list of bytevectors (incoming data)
      (mutable stderr-queue)            ;; list of bytevectors (extended data type 1)
      (mutable eof?)                    ;; received EOF
      (mutable closed?)                 ;; channel closed
      (mutable exit-status)             ;; integer or #f
      (mutable exit-signal))            ;; string or #f
    (protocol
      (lambda (new)
        (lambda (local-id)
          (new local-id #f INITIAL-WINDOW-SIZE 0 0 '() '() #f #f #f #f)))))

  ;; ---- Channel table ----

  (define-record-type channel-table
    (fields
      (mutable channels)     ;; alist: ((local-id . channel) ...)
      (mutable next-id))     ;; next local channel ID
    (protocol
      (lambda (new)
        (lambda ()
          (new '() 0)))))

  (define (channel-table-get table local-id)
    (cond
      [(assv local-id (channel-table-channels table)) => cdr]
      [else #f]))

  (define (channel-table-put! table channel)
    (channel-table-channels-set! table
      (cons (cons (ssh-channel-local-id channel) channel)
            (channel-table-channels table))))

  (define (channel-table-remove! table local-id)
    (channel-table-channels-set! table
      (remp (lambda (p) (= (car p) local-id))
            (channel-table-channels table))))

  (define (channel-table-alloc-id table)
    (let ([id (channel-table-next-id table)])
      (channel-table-next-id-set! table (+ id 1))
      id))

  ;; ---- Channel open ----

  (define (ssh-channel-open-session ts table)
    (let* ([local-id (channel-table-alloc-id table)]
           [ch (make-ssh-channel local-id)])
      (channel-table-put! table ch)
      (ssh-transport-send-packet ts
        (ssh-make-payload SSH_MSG_CHANNEL_OPEN
          (ssh-write-string "session")
          (ssh-write-uint32 local-id)
          (ssh-write-uint32 INITIAL-WINDOW-SIZE)
          (ssh-write-uint32 MAX-PACKET-SIZE)))
      ;; Wait for confirmation (remote-id changes from #f to a number)
      (ssh-channel-dispatch-until ts table
        (lambda () (or (ssh-channel-remote-id ch) (ssh-channel-closed? ch))))
      (when (ssh-channel-closed? ch)
        (error 'ssh-channel-open-session "channel open failed"))
      ch))

  (define (ssh-channel-open-direct-tcpip ts table host port orig-host orig-port)
    (let* ([local-id (channel-table-alloc-id table)]
           [ch (make-ssh-channel local-id)])
      (channel-table-put! table ch)
      (ssh-transport-send-packet ts
        (ssh-make-payload SSH_MSG_CHANNEL_OPEN
          (ssh-write-string "direct-tcpip")
          (ssh-write-uint32 local-id)
          (ssh-write-uint32 INITIAL-WINDOW-SIZE)
          (ssh-write-uint32 MAX-PACKET-SIZE)
          (ssh-write-string host)
          (ssh-write-uint32 port)
          (ssh-write-string orig-host)
          (ssh-write-uint32 orig-port)))
      (ssh-channel-dispatch-until ts table
        (lambda () (or (ssh-channel-remote-id ch) (ssh-channel-closed? ch))))
      (when (ssh-channel-closed? ch)
        (error 'ssh-channel-open-direct-tcpip "channel open failed"))
      ch))

  ;; ---- Channel data ----

  (define (ssh-channel-send-data ts ch data)
    (let ([bv (if (string? data) (string->utf8 data) data)])
      (let loop ([off 0])
        (when (< off (bytevector-length bv))
          (let* ([remaining (- (bytevector-length bv) off)]
                 [send-size (min remaining
                                 (ssh-channel-remote-max-packet ch)
                                 (ssh-channel-remote-window ch))])
            (when (<= send-size 0)
              ;; Window exhausted — need to wait for WINDOW_ADJUST
              ;; For simplicity, just error. A real implementation would wait.
              (error 'ssh-channel-send-data "remote window exhausted"))
            (let ([chunk (make-bytevector send-size)])
              (bytevector-copy! bv off chunk 0 send-size)
              (ssh-transport-send-packet ts
                (ssh-make-payload SSH_MSG_CHANNEL_DATA
                  (ssh-write-uint32 (ssh-channel-remote-id ch))
                  (ssh-write-string chunk)))
              (ssh-channel-remote-window-set! ch
                (- (ssh-channel-remote-window ch) send-size))
              (loop (+ off send-size))))))))

  (define (ssh-channel-send-eof ts ch)
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_CHANNEL_EOF
        (ssh-write-uint32 (ssh-channel-remote-id ch)))))

  (define (ssh-channel-close ts ch)
    (unless (ssh-channel-closed? ch)
      (ssh-transport-send-packet ts
        (ssh-make-payload SSH_MSG_CHANNEL_CLOSE
          (ssh-write-uint32 (ssh-channel-remote-id ch))))
      (ssh-channel-closed?-set! ch #t)))

  ;; ---- Channel read ----

  (define (ssh-channel-read ts table ch)
    ;; Returns next data chunk or #f on EOF
    (let loop ()
      (cond
        [(pair? (ssh-channel-data-queue ch))
         (let ([data (car (ssh-channel-data-queue ch))])
           (ssh-channel-data-queue-set! ch (cdr (ssh-channel-data-queue ch)))
           ;; Send window adjust
           (let ([adjust (bytevector-length data)])
             (ssh-channel-local-window-set! ch
               (+ (ssh-channel-local-window ch) adjust))
             (ssh-transport-send-packet ts
               (ssh-make-payload SSH_MSG_CHANNEL_WINDOW_ADJUST
                 (ssh-write-uint32 (ssh-channel-remote-id ch))
                 (ssh-write-uint32 adjust))))
           data)]
        [(ssh-channel-eof? ch) #f]
        [(ssh-channel-closed? ch) #f]
        [else
         (ssh-channel-dispatch ts table)
         (loop)])))

  (define (ssh-channel-read-stderr ts table ch)
    (let loop ()
      (cond
        [(pair? (ssh-channel-stderr-queue ch))
         (let ([data (car (ssh-channel-stderr-queue ch))])
           (ssh-channel-stderr-queue-set! ch (cdr (ssh-channel-stderr-queue ch)))
           data)]
        [(ssh-channel-eof? ch) #f]
        [(ssh-channel-closed? ch) #f]
        [else
         (ssh-channel-dispatch ts table)
         (loop)])))

  ;; ---- Dispatch ----

  (define (find-channel-by-local-id table local-id)
    (channel-table-get table local-id))

  (define (ssh-channel-dispatch ts table)
    ;; Read and process one incoming packet
    (let* ([pkt (ssh-transport-recv-packet ts)]
           [msg-type (bytevector-u8-ref pkt 0)])
      (case msg-type
        [(91)  ;; SSH_MSG_CHANNEL_OPEN_CONFIRMATION
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)] [off (cdr r1)]
                [r2 (ssh-read-uint32 pkt off)]
                [remote-id (car r2)] [off (cdr r2)]
                [r3 (ssh-read-uint32 pkt off)]
                [remote-window (car r3)] [off (cdr r3)]
                [r4 (ssh-read-uint32 pkt off)]
                [remote-max-packet (car r4)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (ssh-channel-remote-id-set! ch remote-id)
               (ssh-channel-remote-window-set! ch remote-window)
               (ssh-channel-remote-max-packet-set! ch remote-max-packet))))]

        [(92)  ;; SSH_MSG_CHANNEL_OPEN_FAILURE
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (ssh-channel-closed?-set! ch #t))))]

        [(93)  ;; SSH_MSG_CHANNEL_WINDOW_ADJUST
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)] [off (cdr r1)]
                [r2 (ssh-read-uint32 pkt off)]
                [adjust (car r2)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (ssh-channel-remote-window-set! ch
                 (+ (ssh-channel-remote-window ch) adjust)))))]

        [(94)  ;; SSH_MSG_CHANNEL_DATA
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)] [off (cdr r1)]
                [r2 (ssh-read-string pkt off)]
                [data (car r2)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (ssh-channel-data-queue-set! ch
                 (append (ssh-channel-data-queue ch) (list data)))
               (ssh-channel-local-window-set! ch
                 (- (ssh-channel-local-window ch) (bytevector-length data))))))]

        [(95)  ;; SSH_MSG_CHANNEL_EXTENDED_DATA
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)] [off (cdr r1)]
                [r2 (ssh-read-uint32 pkt off)]
                [data-type (car r2)] [off (cdr r2)]
                [r3 (ssh-read-string pkt off)]
                [data (car r3)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (if (= data-type SSH_EXTENDED_DATA_STDERR)
                 (ssh-channel-stderr-queue-set! ch
                   (append (ssh-channel-stderr-queue ch) (list data)))
                 ;; Unknown extended data type — just queue as stderr
                 (ssh-channel-stderr-queue-set! ch
                   (append (ssh-channel-stderr-queue ch) (list data)))))))]

        [(96)  ;; SSH_MSG_CHANNEL_EOF
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (ssh-channel-eof?-set! ch #t))))]

        [(97)  ;; SSH_MSG_CHANNEL_CLOSE
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (ssh-channel-closed?-set! ch #t)
               ;; Send close back if we haven't already
               (unless (ssh-channel-eof? ch)
                 (ssh-channel-eof?-set! ch #t)))))]

        [(98)  ;; SSH_MSG_CHANNEL_REQUEST
         (let* ([off 1]
                [r1 (ssh-read-uint32 pkt off)]
                [local-id (car r1)] [off (cdr r1)]
                [r2 (ssh-read-string pkt off)]
                [req-type (utf8->string (car r2))] [off (cdr r2)]
                [r3 (ssh-read-boolean pkt off)]
                [want-reply (car r3)] [off (cdr r3)])
           (let ([ch (find-channel-by-local-id table local-id)])
             (when ch
               (cond
                 [(string=? req-type "exit-status")
                  (let ([r (ssh-read-uint32 pkt off)])
                    (ssh-channel-exit-status-set! ch (car r)))]
                 [(string=? req-type "exit-signal")
                  (let* ([r (ssh-read-string pkt off)]
                         [signal-name (utf8->string (car r))])
                    (ssh-channel-exit-signal-set! ch signal-name))]
                 [else (void)])
               ;; Reply if requested (for unknown requests, send failure)
               (when want-reply
                 (ssh-transport-send-packet ts
                   (ssh-make-payload SSH_MSG_CHANNEL_FAILURE
                     (ssh-write-uint32 (ssh-channel-remote-id ch))))))))]

        [(99)  ;; SSH_MSG_CHANNEL_SUCCESS — ignore
         (void)]

        [(100) ;; SSH_MSG_CHANNEL_FAILURE — ignore
         (void)]

        [(80)  ;; SSH_MSG_GLOBAL_REQUEST
         (let* ([off 1]
                [r1 (ssh-read-string pkt off)]
                [_req-name (car r1)] [off (cdr r1)]
                [r2 (ssh-read-boolean pkt off)]
                [want-reply (car r2)])
           (when want-reply
             (ssh-transport-send-packet ts
               (ssh-make-payload SSH_MSG_REQUEST_FAILURE))))]

        [(2)   ;; SSH_MSG_IGNORE
         (void)]

        [(4)   ;; SSH_MSG_DEBUG
         (void)]

        [(1)   ;; SSH_MSG_DISCONNECT
         (error 'ssh-channel-dispatch "server disconnected")]

        [else
         ;; Unknown message — send unimplemented
         (void)])))

  (define (ssh-channel-dispatch-until ts table pred)
    (let loop ()
      (unless (pred)
        (ssh-channel-dispatch ts table)
        (loop))))

  ) ;; end library
