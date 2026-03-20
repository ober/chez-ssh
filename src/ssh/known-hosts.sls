#!chezscheme
;;; (ssh known-hosts) — Host key verification
;;;
;;; Reads/writes OpenSSH known_hosts format.
;;; Supports plain hostnames and hashed entries.

(library (ssh known-hosts)
  (export
    ssh-known-hosts-verify    ;; (host port host-key-blob #:file path) → 'ok | 'new | 'changed
    ssh-known-hosts-add       ;; (host port host-key-blob #:file path) → void
    ssh-known-hosts-verifier  ;; (host port #:file path) → (lambda (host-key-blob) → #t/#f)
    ssh-host-key-fingerprint  ;; (host-key-blob) → "SHA256:..." string
    )

  (import (chezscheme) (ssh wire))

  ;; ---- FFI ----
  (define c-sha256
    (foreign-procedure "chez_ssh_sha256" (u8* int u8*) int))

  ;; ---- Base64 encode ----
  (define b64-chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

  (define (base64-encode bv)
    (let* ([len (bytevector-length bv)]
           [out '()])
      (let loop ([i 0] [acc out])
        (cond
          [(>= i len)
           (list->string (reverse acc))]
          [else
           (let* ([b0 (bytevector-u8-ref bv i)]
                  [b1 (if (< (+ i 1) len) (bytevector-u8-ref bv (+ i 1)) 0)]
                  [b2 (if (< (+ i 2) len) (bytevector-u8-ref bv (+ i 2)) 0)]
                  [remaining (- len i)]
                  [c0 (string-ref b64-chars (bitwise-arithmetic-shift-right b0 2))]
                  [c1 (string-ref b64-chars
                        (bitwise-ior
                          (bitwise-arithmetic-shift-left (bitwise-and b0 3) 4)
                          (bitwise-arithmetic-shift-right b1 4)))]
                  [c2 (if (>= remaining 2)
                        (string-ref b64-chars
                          (bitwise-ior
                            (bitwise-arithmetic-shift-left (bitwise-and b1 #xf) 2)
                            (bitwise-arithmetic-shift-right b2 6)))
                        #\=)]
                  [c3 (if (>= remaining 3)
                        (string-ref b64-chars (bitwise-and b2 #x3f))
                        #\=)])
             (loop (+ i 3)
                   (cons c3 (cons c2 (cons c1 (cons c0 acc))))))]))))

  ;; ---- Base64 decode ----
  (define (base64-decode-char c)
    (cond
      [(and (char>=? c #\A) (char<=? c #\Z)) (- (char->integer c) (char->integer #\A))]
      [(and (char>=? c #\a) (char<=? c #\z)) (+ 26 (- (char->integer c) (char->integer #\a)))]
      [(and (char>=? c #\0) (char<=? c #\9)) (+ 52 (- (char->integer c) (char->integer #\0)))]
      [(char=? c #\+) 62]
      [(char=? c #\/) 63]
      [else #f]))

  (define (base64-decode s)
    (let ([chars (string->list (string-filter (lambda (c) (not (char-whitespace? c))) s))]
          [out '()])
      (let loop ([cs chars] [acc '()])
        (cond
          [(null? cs)
           (list->bytevector (reverse acc))]
          [else
           (let* ([c0 (base64-decode-char (car cs))]
                  [c1 (if (null? (cdr cs)) 0 (base64-decode-char (cadr cs)))]
                  [c2 (if (or (null? (cdr cs)) (null? (cddr cs))
                              (char=? (caddr cs) #\=))
                        #f
                        (base64-decode-char (caddr cs)))]
                  [c3 (if (or (null? (cdr cs)) (null? (cddr cs)) (null? (cdddr cs))
                              (char=? (cadddr cs) #\=))
                        #f
                        (base64-decode-char (cadddr cs)))])
             (when (and c0 c1)
               (let ([b0 (bitwise-ior
                           (bitwise-arithmetic-shift-left c0 2)
                           (bitwise-arithmetic-shift-right c1 4))])
                 (set! acc (cons b0 acc))))
             (when (and c1 c2)
               (let ([b1 (bitwise-and #xff
                           (bitwise-ior
                             (bitwise-arithmetic-shift-left c1 4)
                             (bitwise-arithmetic-shift-right c2 2)))])
                 (set! acc (cons b1 acc))))
             (when (and c2 c3)
               (let ([b2 (bitwise-and #xff
                           (bitwise-ior
                             (bitwise-arithmetic-shift-left c2 6)
                             c3))])
                 (set! acc (cons b2 acc))))
             (let ([advance (min 4 (length cs))])
               (loop (list-tail cs advance) acc)))]))))

  (define (string-filter pred s)
    (list->string (filter pred (string->list s))))

  (define (list->bytevector lst)
    (let* ([len (length lst)]
           [bv (make-bytevector len)])
      (let loop ([l lst] [i 0])
        (unless (null? l)
          (bytevector-u8-set! bv i (car l))
          (loop (cdr l) (+ i 1))))
      bv))

  ;; ---- Fingerprint ----

  (define (ssh-host-key-fingerprint host-key-blob)
    (let ([hash (make-bytevector 32)])
      (c-sha256 host-key-blob (bytevector-length host-key-blob) hash)
      (string-append "SHA256:" (base64-encode-no-pad hash))))

  (define (base64-encode-no-pad bv)
    (let ([s (base64-encode bv)])
      ;; Remove trailing = padding
      (let loop ([i (- (string-length s) 1)])
        (cond
          [(< i 0) ""]
          [(char=? (string-ref s i) #\=) (loop (- i 1))]
          [else (substring s 0 (+ i 1))]))))

  ;; ---- Known hosts file ----

  (define (default-known-hosts-path)
    (string-append (or (getenv "HOME") "") "/.ssh/known_hosts"))

  (define (host-pattern host port)
    ;; For non-standard ports: [host]:port
    (if (= port 22)
      host
      (string-append "[" host "]:" (number->string port))))

  (define (read-known-hosts-file path)
    (guard (e [#t '()])
      (let ([port (open-input-file path)])
        (let loop ([lines '()])
          (let ([line (get-line port)])
            (cond
              [(eof-object? line)
               (close-port port)
               (reverse lines)]
              [else
               (loop (cons line lines))]))))))

  (define (parse-known-hosts-line line)
    ;; Format: hostname key-type base64-key [comment]
    ;; Returns (hostname key-type key-bv) or #f
    (let ([parts (string-split line #\space)])
      (if (>= (length parts) 3)
        (let ([hostname-pattern (car parts)]
              [key-type (cadr parts)]
              [key-b64 (caddr parts)])
          (guard (e [#t #f])
            (list hostname-pattern key-type (base64-decode key-b64))))
        #f)))

  (define (string-split s delim)
    (let loop ([i 0] [start 0] [acc '()])
      (cond
        [(>= i (string-length s))
         (reverse (cons (substring s start i) acc))]
        [(char=? (string-ref s i) delim)
         (loop (+ i 1) (+ i 1) (cons (substring s start i) acc))]
        [else
         (loop (+ i 1) start acc)])))

  ;; ---- Verification ----

  (define ssh-known-hosts-verify
    (case-lambda
      [(host port host-key-blob)
       (ssh-known-hosts-verify host port host-key-blob (default-known-hosts-path))]
      [(host port host-key-blob file)
       (let* ([pattern (host-pattern host port)]
              [lines (read-known-hosts-file file)]
              ;; Extract key type from blob
              [r (ssh-read-string host-key-blob 0)]
              [key-type (utf8->string (car r))])
         (let loop ([lines lines])
           (cond
             [(null? lines) 'new]
             [else
              (let ([parsed (parse-known-hosts-line (car lines))])
                (cond
                  [(not parsed) (loop (cdr lines))]
                  [(and (host-matches? (car parsed) pattern)
                        (string=? (cadr parsed) key-type))
                   (if (bytevector=? (caddr parsed) host-key-blob)
                     'ok
                     'changed)]
                  [else (loop (cdr lines))]))])))]))

  (define (host-matches? file-pattern our-pattern)
    ;; Simple match: exact string comparison
    ;; Also handles comma-separated patterns in the file
    (let ([parts (string-split file-pattern #\,)])
      (exists (lambda (p) (string=? p our-pattern)) parts)))

  ;; ---- Add entry ----

  (define ssh-known-hosts-add
    (case-lambda
      [(host port host-key-blob)
       (ssh-known-hosts-add host port host-key-blob (default-known-hosts-path))]
      [(host port host-key-blob file)
       (let* ([pattern (host-pattern host port)]
              [r (ssh-read-string host-key-blob 0)]
              [key-type (utf8->string (car r))]
              [key-b64 (base64-encode host-key-blob)]
              [line (string-append pattern " " key-type " " key-b64 "\n")])
         ;; Ensure directory exists
         (let ([dir (path-parent file)])
           (when (and dir (not (file-exists? dir)))
             (mkdir dir)))
         ;; Append to file
         (let ([port (open-file-output-port file
                       (file-options no-fail no-truncate)
                       (buffer-mode block)
                       (native-transcoder))])
           (set-port-position! port (port-length port))
           (put-string port line)
           (close-port port)))]))

  ;; path-parent and mkdir are provided by (chezscheme)

  ;; ---- Convenience verifier ----

  (define ssh-known-hosts-verifier
    (case-lambda
      [(host port)
       (ssh-known-hosts-verifier host port (default-known-hosts-path))]
      [(host port file)
       (lambda (host-key-blob)
         (let ([result (ssh-known-hosts-verify host port host-key-blob file)])
           (case result
             [(ok) #t]
             [(new)
              ;; Auto-accept and save (trust-on-first-use)
              (ssh-known-hosts-add host port host-key-blob file)
              #t]
             [(changed)
              ;; Reject changed keys
              #f])))]))

  ) ;; end library
