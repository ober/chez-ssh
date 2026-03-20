#!chezscheme
;;; (ssh sftp) — SFTP v3 protocol (draft-ietf-secsh-filexfer-02)
;;;
;;; File/directory operations over an SSH subsystem channel.

(library (ssh sftp)
  (export
    ;; Session management
    ssh-sftp-open-session      ;; (ts table) → sftp-session
    ssh-sftp-close-session     ;; (ts table sftp) → void

    ;; File operations
    ssh-sftp-open              ;; (sftp path flags #:mode) → handle
    ssh-sftp-close-handle      ;; (sftp handle) → void
    ssh-sftp-read              ;; (sftp handle offset length) → bytevector or #f
    ssh-sftp-write             ;; (sftp handle offset data) → void
    ssh-sftp-stat              ;; (sftp path) → attrs or #f
    ssh-sftp-fstat             ;; (sftp handle) → attrs or #f
    ssh-sftp-setstat           ;; (sftp path attrs) → void
    ssh-sftp-remove            ;; (sftp path) → void
    ssh-sftp-rename            ;; (sftp old new) → void

    ;; Directory operations
    ssh-sftp-mkdir             ;; (sftp path #:mode) → void
    ssh-sftp-rmdir             ;; (sftp path) → void
    ssh-sftp-opendir           ;; (sftp path) → handle
    ssh-sftp-readdir           ;; (sftp handle) → list of (name longname attrs) or #f
    ssh-sftp-list-directory    ;; (sftp path) → list of (name longname attrs)

    ;; Path operations
    ssh-sftp-realpath          ;; (sftp path) → resolved-path

    ;; High-level
    ssh-sftp-get               ;; (sftp remote-path local-path) → void
    ssh-sftp-put               ;; (sftp local-path remote-path) → void

    ;; SFTP attrs
    make-sftp-attrs
    sftp-attrs?
    sftp-attrs-size
    sftp-attrs-uid
    sftp-attrs-gid
    sftp-attrs-permissions
    sftp-attrs-atime
    sftp-attrs-mtime

    ;; SFTP flags
    SSH_FXF_READ
    SSH_FXF_WRITE
    SSH_FXF_APPEND
    SSH_FXF_CREAT
    SSH_FXF_TRUNC
    SSH_FXF_EXCL
    )

  (import (chezscheme) (ssh wire) (ssh transport) (ssh channel) (ssh session))

  ;; ---- SFTP constants ----

  ;; Packet types
  (define SSH_FXP_INIT         1)
  (define SSH_FXP_VERSION      2)
  (define SSH_FXP_OPEN         3)
  (define SSH_FXP_CLOSE        4)
  (define SSH_FXP_READ         5)
  (define SSH_FXP_WRITE        6)
  (define SSH_FXP_LSTAT        7)
  (define SSH_FXP_FSTAT        8)
  (define SSH_FXP_SETSTAT      9)
  (define SSH_FXP_OPENDIR      11)
  (define SSH_FXP_READDIR      12)
  (define SSH_FXP_REMOVE       13)
  (define SSH_FXP_MKDIR        14)
  (define SSH_FXP_RMDIR        15)
  (define SSH_FXP_REALPATH     16)
  (define SSH_FXP_STAT         17)
  (define SSH_FXP_RENAME       18)
  (define SSH_FXP_STATUS       101)
  (define SSH_FXP_HANDLE       102)
  (define SSH_FXP_DATA         103)
  (define SSH_FXP_NAME         104)
  (define SSH_FXP_ATTRS        105)

  ;; Status codes
  (define SSH_FX_OK            0)
  (define SSH_FX_EOF           1)
  (define SSH_FX_NO_SUCH_FILE  2)
  (define SSH_FX_PERMISSION_DENIED 3)

  ;; Open flags
  (define SSH_FXF_READ         #x00000001)
  (define SSH_FXF_WRITE        #x00000002)
  (define SSH_FXF_APPEND       #x00000004)
  (define SSH_FXF_CREAT        #x00000008)
  (define SSH_FXF_TRUNC        #x00000010)
  (define SSH_FXF_EXCL         #x00000020)

  ;; Attr flags
  (define SSH_FILEXFER_ATTR_SIZE        #x00000001)
  (define SSH_FILEXFER_ATTR_UIDGID      #x00000002)
  (define SSH_FILEXFER_ATTR_PERMISSIONS #x00000004)
  (define SSH_FILEXFER_ATTR_ACMODTIME   #x00000008)

  ;; ---- Records ----

  (define-record-type sftp-session
    (fields
      ts         ;; transport-state
      table      ;; channel-table
      channel    ;; ssh-channel (subsystem channel)
      (mutable next-id))  ;; request ID counter
    (protocol
      (lambda (new)
        (lambda (ts table ch)
          (new ts table ch 1)))))

  (define-record-type sftp-attrs
    (fields
      size         ;; integer or #f
      uid          ;; integer or #f
      gid          ;; integer or #f
      permissions  ;; integer or #f
      atime        ;; integer or #f
      mtime))      ;; integer or #f

  ;; ---- SFTP packet I/O ----

  (define (sftp-next-id sftp)
    (let ([id (sftp-session-next-id sftp)])
      (sftp-session-next-id-set! sftp (+ id 1))
      id))

  (define (sftp-send sftp payload)
    ;; SFTP packets are framed with a 4-byte length prefix over the channel
    (let* ([len (bytevector-length payload)]
           [frame (make-bytevector (+ 4 len))])
      (let ([hdr (ssh-write-uint32 len)])
        (bytevector-copy! hdr 0 frame 0 4))
      (bytevector-copy! payload 0 frame 4 len)
      (ssh-channel-send-data (sftp-session-ts sftp)
                             (sftp-session-channel sftp)
                             frame)))

  (define (sftp-recv sftp)
    ;; Read one SFTP packet from channel data
    ;; First read 4-byte length, then payload
    (let* ([ts (sftp-session-ts sftp)]
           [table (sftp-session-table sftp)]
           [ch (sftp-session-channel sftp)]
           [len-data (sftp-channel-read-exact sftp 4)]
           [pkt-len (car (ssh-read-uint32 len-data 0))]
           [payload (sftp-channel-read-exact sftp pkt-len)])
      payload))

  ;; Read exactly n bytes from SFTP channel, buffering partial reads
  (define (sftp-channel-read-exact sftp n)
    (let ([ts (sftp-session-ts sftp)]
          [table (sftp-session-table sftp)]
          [ch (sftp-session-channel sftp)])
      (let loop ([collected '()] [remaining n])
        (if (<= remaining 0)
          (bytevector-concat (reverse collected) n)
          (let ([data (ssh-channel-read ts table ch)])
            (if (not data)
              (error 'sftp-channel-read-exact "unexpected EOF")
              (let ([got (bytevector-length data)])
                (if (> got remaining)
                  ;; Got more than needed — push excess back
                  (let ([needed (make-bytevector remaining)]
                        [excess (make-bytevector (- got remaining))])
                    (bytevector-copy! data 0 needed 0 remaining)
                    (bytevector-copy! data remaining excess 0 (- got remaining))
                    ;; Push excess back to channel data queue
                    (ssh-channel-data-queue-set! ch
                      (cons excess (ssh-channel-data-queue ch)))
                    (bytevector-concat (reverse (cons needed collected)) n))
                  (loop (cons data collected) (- remaining got))))))))))

  (define (bytevector-concat bvs total-len)
    (let ([result (make-bytevector total-len)])
      (let loop ([bvs bvs] [off 0])
        (unless (null? bvs)
          (let* ([bv (car bvs)]
                 [len (min (bytevector-length bv) (- total-len off))])
            (bytevector-copy! bv 0 result off len)
            (loop (cdr bvs) (+ off len)))))
      result))

  ;; ---- Attrs encoding/decoding ----

  (define (encode-attrs attrs)
    (let ([flags 0]
          [parts '()])
      (when (sftp-attrs-size attrs)
        (set! flags (bitwise-ior flags SSH_FILEXFER_ATTR_SIZE))
        (set! parts (cons (ssh-write-uint64 (sftp-attrs-size attrs)) parts)))
      (when (and (sftp-attrs-uid attrs) (sftp-attrs-gid attrs))
        (set! flags (bitwise-ior flags SSH_FILEXFER_ATTR_UIDGID))
        (set! parts (cons (ssh-write-uint32 (sftp-attrs-gid attrs)) parts))
        (set! parts (cons (ssh-write-uint32 (sftp-attrs-uid attrs)) parts)))
      (when (sftp-attrs-permissions attrs)
        (set! flags (bitwise-ior flags SSH_FILEXFER_ATTR_PERMISSIONS))
        (set! parts (cons (ssh-write-uint32 (sftp-attrs-permissions attrs)) parts)))
      (when (and (sftp-attrs-atime attrs) (sftp-attrs-mtime attrs))
        (set! flags (bitwise-ior flags SSH_FILEXFER_ATTR_ACMODTIME))
        (set! parts (cons (ssh-write-uint32 (sftp-attrs-mtime attrs)) parts))
        (set! parts (cons (ssh-write-uint32 (sftp-attrs-atime attrs)) parts)))
      (apply bytevector-append (ssh-write-uint32 flags) (reverse parts))))

  (define (decode-attrs bv off)
    ;; Returns (attrs . new-offset)
    (let* ([r (ssh-read-uint32 bv off)]
           [flags (car r)] [off (cdr r)]
           [size #f] [uid #f] [gid #f] [perms #f] [atime #f] [mtime #f])
      (when (not (= 0 (bitwise-and flags SSH_FILEXFER_ATTR_SIZE)))
        (let ([r (ssh-read-uint64 bv off)])
          (set! size (car r))
          (set! off (cdr r))))
      (when (not (= 0 (bitwise-and flags SSH_FILEXFER_ATTR_UIDGID)))
        (let* ([r1 (ssh-read-uint32 bv off)]
               [r2 (ssh-read-uint32 bv (cdr r1))])
          (set! uid (car r1))
          (set! gid (car r2))
          (set! off (cdr r2))))
      (when (not (= 0 (bitwise-and flags SSH_FILEXFER_ATTR_PERMISSIONS)))
        (let ([r (ssh-read-uint32 bv off)])
          (set! perms (car r))
          (set! off (cdr r))))
      (when (not (= 0 (bitwise-and flags SSH_FILEXFER_ATTR_ACMODTIME)))
        (let* ([r1 (ssh-read-uint32 bv off)]
               [r2 (ssh-read-uint32 bv (cdr r1))])
          (set! atime (car r1))
          (set! mtime (car r2))
          (set! off (cdr r2))))
      (cons (make-sftp-attrs size uid gid perms atime mtime) off)))

  ;; uint64 read/write
  (define (ssh-write-uint64 n)
    (let ([bv (make-bytevector 8)])
      (bytevector-u8-set! bv 0 (bitwise-and (bitwise-arithmetic-shift-right n 56) #xff))
      (bytevector-u8-set! bv 1 (bitwise-and (bitwise-arithmetic-shift-right n 48) #xff))
      (bytevector-u8-set! bv 2 (bitwise-and (bitwise-arithmetic-shift-right n 40) #xff))
      (bytevector-u8-set! bv 3 (bitwise-and (bitwise-arithmetic-shift-right n 32) #xff))
      (bytevector-u8-set! bv 4 (bitwise-and (bitwise-arithmetic-shift-right n 24) #xff))
      (bytevector-u8-set! bv 5 (bitwise-and (bitwise-arithmetic-shift-right n 16) #xff))
      (bytevector-u8-set! bv 6 (bitwise-and (bitwise-arithmetic-shift-right n 8) #xff))
      (bytevector-u8-set! bv 7 (bitwise-and n #xff))
      bv))

  (define (ssh-read-uint64 bv offset)
    (when (> (+ offset 8) (bytevector-length bv))
      (error 'ssh-read-uint64 "buffer underflow" offset))
    (let ([n (bitwise-ior
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv offset) 56)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 1)) 48)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 2)) 40)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 3)) 32)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 4)) 24)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 5)) 16)
               (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ offset 6)) 8)
               (bytevector-u8-ref bv (+ offset 7)))])
      (cons n (+ offset 8))))

  ;; ---- Session management ----

  (define (ssh-sftp-open-session ts table)
    (let ([ch (ssh-channel-open-session ts table)])
      ;; Request sftp subsystem
      (ssh-session-subsystem ts table ch "sftp")
      ;; Wait for channel success (dispatch a few packets)
      (ssh-channel-dispatch ts table)
      ;; Send SFTP INIT
      (let ([sftp (make-sftp-session ts table ch)])
        (sftp-send sftp
          (bytevector-append
            (ssh-write-byte SSH_FXP_INIT)
            (ssh-write-uint32 3)))  ;; version 3
        ;; Receive VERSION
        (let* ([reply (sftp-recv sftp)]
               [type (bytevector-u8-ref reply 0)])
          (unless (= type SSH_FXP_VERSION)
            (error 'ssh-sftp-open-session "expected SFTP VERSION" type))
          sftp))))

  (define (ssh-sftp-close-session ts table sftp)
    (ssh-channel-send-eof ts (sftp-session-channel sftp))
    (ssh-channel-close ts (sftp-session-channel sftp)))

  ;; ---- Check status response ----

  (define (sftp-check-status reply expected-id operation)
    (let ([type (bytevector-u8-ref reply 0)])
      (when (= type SSH_FXP_STATUS)
        (let* ([off 1]
               [r1 (ssh-read-uint32 reply off)]
               [id (car r1)] [off (cdr r1)]
               [r2 (ssh-read-uint32 reply off)]
               [code (car r2)] [off (cdr r2)])
          (unless (= code SSH_FX_OK)
            (let* ([r3 (ssh-read-string reply off)]
                   [msg (utf8->string (car r3))])
              (error operation msg code)))))))

  ;; ---- File operations ----

  (define ssh-sftp-open
    (case-lambda
      [(sftp path flags) (ssh-sftp-open sftp path flags #o644)]
      [(sftp path flags mode)
       (let ([id (sftp-next-id sftp)])
         (sftp-send sftp
           (bytevector-append
             (ssh-write-byte SSH_FXP_OPEN)
             (ssh-write-uint32 id)
             (ssh-write-string path)
             (ssh-write-uint32 flags)
             (encode-attrs (make-sftp-attrs #f #f #f mode #f #f))))
         (let* ([reply (sftp-recv sftp)]
                [type (bytevector-u8-ref reply 0)])
           (cond
             [(= type SSH_FXP_HANDLE)
              (let* ([off 1]
                     [r1 (ssh-read-uint32 reply off)]
                     [_id (car r1)] [off (cdr r1)]
                     [r2 (ssh-read-string reply off)])
                (car r2))]  ;; handle bytevector
             [else
              (sftp-check-status reply id 'ssh-sftp-open)
              #f])))]))

  (define (ssh-sftp-close-handle sftp handle)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_CLOSE)
          (ssh-write-uint32 id)
          (ssh-write-string handle)))
      (let ([reply (sftp-recv sftp)])
        (sftp-check-status reply id 'ssh-sftp-close-handle))))

  (define (ssh-sftp-read sftp handle offset length)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_READ)
          (ssh-write-uint32 id)
          (ssh-write-string handle)
          (ssh-write-uint64 offset)
          (ssh-write-uint32 length)))
      (let* ([reply (sftp-recv sftp)]
             [type (bytevector-u8-ref reply 0)])
        (cond
          [(= type SSH_FXP_DATA)
           (let* ([off 1]
                  [r1 (ssh-read-uint32 reply off)]
                  [_id (car r1)] [off (cdr r1)]
                  [r2 (ssh-read-string reply off)])
             (car r2))]
          [(= type SSH_FXP_STATUS)
           (let* ([off 1]
                  [r1 (ssh-read-uint32 reply off)]
                  [_id (car r1)] [off (cdr r1)]
                  [r2 (ssh-read-uint32 reply off)]
                  [code (car r2)])
             (if (= code SSH_FX_EOF) #f
               (error 'ssh-sftp-read "read failed" code)))]
          [else #f]))))

  (define (ssh-sftp-write sftp handle offset data)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_WRITE)
          (ssh-write-uint32 id)
          (ssh-write-string handle)
          (ssh-write-uint64 offset)
          (ssh-write-string data)))
      (let ([reply (sftp-recv sftp)])
        (sftp-check-status reply id 'ssh-sftp-write))))

  (define (ssh-sftp-stat sftp path)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_STAT)
          (ssh-write-uint32 id)
          (ssh-write-string path)))
      (let* ([reply (sftp-recv sftp)]
             [type (bytevector-u8-ref reply 0)])
        (cond
          [(= type SSH_FXP_ATTRS)
           (let* ([off 1]
                  [r (ssh-read-uint32 reply off)]
                  [_id (car r)] [off (cdr r)])
             (car (decode-attrs reply off)))]
          [else #f]))))

  (define (ssh-sftp-fstat sftp handle)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_FSTAT)
          (ssh-write-uint32 id)
          (ssh-write-string handle)))
      (let* ([reply (sftp-recv sftp)]
             [type (bytevector-u8-ref reply 0)])
        (cond
          [(= type SSH_FXP_ATTRS)
           (let* ([off 1]
                  [r (ssh-read-uint32 reply off)]
                  [_id (car r)] [off (cdr r)])
             (car (decode-attrs reply off)))]
          [else #f]))))

  (define (ssh-sftp-setstat sftp path attrs)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_SETSTAT)
          (ssh-write-uint32 id)
          (ssh-write-string path)
          (encode-attrs attrs)))
      (let ([reply (sftp-recv sftp)])
        (sftp-check-status reply id 'ssh-sftp-setstat))))

  (define (ssh-sftp-remove sftp path)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_REMOVE)
          (ssh-write-uint32 id)
          (ssh-write-string path)))
      (let ([reply (sftp-recv sftp)])
        (sftp-check-status reply id 'ssh-sftp-remove))))

  (define (ssh-sftp-rename sftp old-path new-path)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_RENAME)
          (ssh-write-uint32 id)
          (ssh-write-string old-path)
          (ssh-write-string new-path)))
      (let ([reply (sftp-recv sftp)])
        (sftp-check-status reply id 'ssh-sftp-rename))))

  ;; ---- Directory operations ----

  (define ssh-sftp-mkdir
    (case-lambda
      [(sftp path) (ssh-sftp-mkdir sftp path #o755)]
      [(sftp path mode)
       (let ([id (sftp-next-id sftp)])
         (sftp-send sftp
           (bytevector-append
             (ssh-write-byte SSH_FXP_MKDIR)
             (ssh-write-uint32 id)
             (ssh-write-string path)
             (encode-attrs (make-sftp-attrs #f #f #f mode #f #f))))
         (let ([reply (sftp-recv sftp)])
           (sftp-check-status reply id 'ssh-sftp-mkdir)))]))

  (define (ssh-sftp-rmdir sftp path)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_RMDIR)
          (ssh-write-uint32 id)
          (ssh-write-string path)))
      (let ([reply (sftp-recv sftp)])
        (sftp-check-status reply id 'ssh-sftp-rmdir))))

  (define (ssh-sftp-opendir sftp path)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_OPENDIR)
          (ssh-write-uint32 id)
          (ssh-write-string path)))
      (let* ([reply (sftp-recv sftp)]
             [type (bytevector-u8-ref reply 0)])
        (cond
          [(= type SSH_FXP_HANDLE)
           (let* ([off 1]
                  [r1 (ssh-read-uint32 reply off)]
                  [_id (car r1)] [off (cdr r1)]
                  [r2 (ssh-read-string reply off)])
             (car r2))]
          [else
           (sftp-check-status reply id 'ssh-sftp-opendir)
           #f]))))

  (define (ssh-sftp-readdir sftp handle)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_READDIR)
          (ssh-write-uint32 id)
          (ssh-write-string handle)))
      (let* ([reply (sftp-recv sftp)]
             [type (bytevector-u8-ref reply 0)])
        (cond
          [(= type SSH_FXP_NAME)
           (let* ([off 1]
                  [r1 (ssh-read-uint32 reply off)]
                  [_id (car r1)] [off (cdr r1)]
                  [r2 (ssh-read-uint32 reply off)]
                  [count (car r2)] [off (cdr r2)])
             (let loop ([i 0] [off off] [entries '()])
               (if (>= i count)
                 (reverse entries)
                 (let* ([r (ssh-read-string reply off)]
                        [name (utf8->string (car r))] [off (cdr r)]
                        [r2 (ssh-read-string reply off)]
                        [longname (utf8->string (car r2))] [off (cdr r2)]
                        [r3 (decode-attrs reply off)]
                        [attrs (car r3)] [off (cdr r3)])
                   (loop (+ i 1) off
                         (cons (list name longname attrs) entries))))))]
          [(= type SSH_FXP_STATUS)
           (let* ([off 1]
                  [r1 (ssh-read-uint32 reply off)]
                  [_id (car r1)] [off (cdr r1)]
                  [r2 (ssh-read-uint32 reply off)]
                  [code (car r2)])
             (if (= code SSH_FX_EOF) #f
               (error 'ssh-sftp-readdir "readdir failed" code)))]
          [else #f]))))

  (define (ssh-sftp-list-directory sftp path)
    (let ([handle (ssh-sftp-opendir sftp path)])
      (let loop ([all-entries '()])
        (let ([entries (ssh-sftp-readdir sftp handle)])
          (if entries
            (loop (append all-entries entries))
            (begin
              (ssh-sftp-close-handle sftp handle)
              all-entries))))))

  ;; ---- Path operations ----

  (define (ssh-sftp-realpath sftp path)
    (let ([id (sftp-next-id sftp)])
      (sftp-send sftp
        (bytevector-append
          (ssh-write-byte SSH_FXP_REALPATH)
          (ssh-write-uint32 id)
          (ssh-write-string path)))
      (let* ([reply (sftp-recv sftp)]
             [type (bytevector-u8-ref reply 0)])
        (cond
          [(= type SSH_FXP_NAME)
           (let* ([off 1]
                  [r1 (ssh-read-uint32 reply off)]
                  [_id (car r1)] [off (cdr r1)]
                  [r2 (ssh-read-uint32 reply off)]
                  [_count (car r2)] [off (cdr r2)]
                  [r3 (ssh-read-string reply off)]
                  [resolved (utf8->string (car r3))])
             resolved)]
          [else
           (sftp-check-status reply id 'ssh-sftp-realpath)
           #f]))))

  ;; ---- High-level file transfer ----

  (define (ssh-sftp-get sftp remote-path local-path)
    ;; Download remote file to local path
    (let* ([handle (ssh-sftp-open sftp remote-path SSH_FXF_READ)]
           [out-port (open-file-output-port local-path
                       (file-options no-fail)
                       (buffer-mode block))])
      (let loop ([offset 0])
        (let ([data (ssh-sftp-read sftp handle offset 32768)])
          (when data
            (put-bytevector out-port data)
            (loop (+ offset (bytevector-length data))))))
      (close-port out-port)
      (ssh-sftp-close-handle sftp handle)))

  (define (ssh-sftp-put sftp local-path remote-path)
    ;; Upload local file to remote path
    (let* ([in-port (open-file-input-port local-path)]
           [handle (ssh-sftp-open sftp remote-path
                     (bitwise-ior SSH_FXF_WRITE SSH_FXF_CREAT SSH_FXF_TRUNC))])
      (let loop ([offset 0])
        (let ([data (get-bytevector-n in-port 32768)])
          (unless (eof-object? data)
            (ssh-sftp-write sftp handle offset data)
            (loop (+ offset (bytevector-length data))))))
      (close-port in-port)
      (ssh-sftp-close-handle sftp handle)))

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
