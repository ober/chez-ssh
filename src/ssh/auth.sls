#!chezscheme
;;; (ssh auth) — SSH user authentication (RFC 4252)
;;;
;;; Supports: publickey (ed25519), password, keyboard-interactive

(library (ssh auth)
  (export
    ssh-auth-publickey      ;; (ts username seed-bv) → #t or error
    ssh-auth-password       ;; (ts username password) → #t or error
    ssh-auth-interactive    ;; (ts username response-callback) → #t or error
    ssh-userauth-request    ;; request ssh-userauth service
    )

  (import (chezscheme) (ssh wire) (ssh transport))

  ;; ---- FFI ----
  (define c-ed25519-sign
    (foreign-procedure "chez_ssh_ed25519_sign" (u8* u8* int u8*) int))

  ;; ---- Service request ----

  (define (ssh-userauth-request ts)
    ;; Request the ssh-userauth service
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_SERVICE_REQUEST
        (ssh-write-string "ssh-userauth")))
    (let ([reply (ssh-transport-recv-packet ts)])
      (unless (= (bytevector-u8-ref reply 0) SSH_MSG_SERVICE_ACCEPT)
        (error 'ssh-userauth-request "service request denied"
               (bytevector-u8-ref reply 0)))
      #t))

  ;; ---- Public key authentication ----

  (define (ssh-auth-publickey ts username seed-bv)
    ;; seed-bv: 32-byte Ed25519 seed
    ;; First derive the public key
    (let ([pubkey (make-bytevector 32)])
      ;; Derive pubkey via sign of empty data (actually use the FFI)
      ;; We need a derive function. Let's compute it from the sign function
      ;; by using the existing shim. Actually, let's add ed25519_sign to crypto.
      ;; We already have chez_ssh_ed25519_sign in crypto.c.
      ;; For pubkey derivation, we can use the existing shim or add a derive function.
      ;; For now, let's just build the pubkey blob and use the sign function.

      ;; Actually, we need ed25519 derive. Let's use the sign module differently.
      ;; The transport already loaded chez_ssh_crypto.so. Let's use an FFI for derive too.
      ;; But chez_ssh_crypto.c doesn't have a derive function. We can compute it
      ;; by signing something and extracting, but that's wasteful.
      ;; Better: just re-use the chez_ssh_shim.c's ed25519_derive_pubkey.
      ;; Or add one to crypto.c. For now, load from the shim.

      ;; Use OpenSSL's EVP to derive pubkey from seed
      ;; Actually chez_ssh_ed25519_sign already loads the seed as a private key.
      ;; Let's just derive it via the existing shim's function.
      ;; For simplicity, the caller should provide both seed and pubkey.
      ;; Let's change the API to take pubkey too, or derive it here.
      ;; Best approach: add a simple derive wrapper. But since the shim already has one,
      ;; let's just bind it.
      (c-ed25519-derive-pubkey seed-bv pubkey)

      ;; Build the public key blob: string("ssh-ed25519") || string(pubkey32)
      (let* ([key-type "ssh-ed25519"]
             [pubkey-blob (bytevector-append
                            (ssh-write-string key-type)
                            (ssh-write-string pubkey))]
             [session-id (transport-state-session-id ts)])

        ;; Step 1: Send publickey query (without signature) to check if method is acceptable
        ;; Actually, we can skip the query and go straight to signing. More efficient.

        ;; Build the signature data per RFC 4252 §7:
        ;; string    session identifier
        ;; byte      SSH_MSG_USERAUTH_REQUEST
        ;; string    user name
        ;; string    service name ("ssh-connection")
        ;; string    "publickey"
        ;; boolean   TRUE
        ;; string    public key algorithm name
        ;; string    public key blob
        (let* ([sig-data (bytevector-append
                           (ssh-write-string session-id)
                           (ssh-write-byte SSH_MSG_USERAUTH_REQUEST)
                           (ssh-write-string username)
                           (ssh-write-string "ssh-connection")
                           (ssh-write-string "publickey")
                           (ssh-write-boolean #t)
                           (ssh-write-string key-type)
                           (ssh-write-string pubkey-blob))]
               ;; Sign it
               [sig (make-bytevector 64)]
               [rc (c-ed25519-sign seed-bv sig-data (bytevector-length sig-data) sig)])
          (when (< rc 0)
            (error 'ssh-auth-publickey "signing failed"))

          ;; Build signature blob: string("ssh-ed25519") || string(sig64)
          (let ([sig-blob (bytevector-append
                            (ssh-write-string key-type)
                            (ssh-write-string sig))])

            ;; Send USERAUTH_REQUEST with signature
            (ssh-transport-send-packet ts
              (ssh-make-payload SSH_MSG_USERAUTH_REQUEST
                (ssh-write-string username)
                (ssh-write-string "ssh-connection")
                (ssh-write-string "publickey")
                (ssh-write-boolean #t)
                (ssh-write-string key-type)
                (ssh-write-string pubkey-blob)
                (ssh-write-string sig-blob)))

            ;; Process response
            (handle-auth-response ts 'publickey))))))

  ;; ---- Pubkey derivation FFI ----
  ;; Use the same function from chez_ssh_crypto.so (sign already loaded)
  ;; We need a separate derive function. Let's bind it if available,
  ;; or compute from sign.

  ;; Actually, we can add a small wrapper: sign empty data and the pubkey
  ;; comes from the EVP_PKEY. But that's hacky.
  ;; Better: the sign function in crypto.c creates EVP_PKEY from seed,
  ;; which internally derives pubkey. Let's just add a derive export.
  ;; For now, import from the shim which has one.

  ;; The shim has ed25519_derive_pubkey as a static function.
  ;; We need to expose it. But modifying the shim is in the plan.
  ;; For now, let's define our own via OpenSSL in a direct FFI call.

  ;; Actually, the simplest approach: use the chez_ssh_crypto.so sign function
  ;; indirectly. We don't need a separate derive — we can get the pubkey
  ;; from OpenSSL by creating the key and extracting the public part.
  ;; Let's add it to crypto.c later. For now, use a workaround.

  ;; The cleanest fix: chez_ssh_ed25519_sign in crypto.c creates an EVP_PKEY.
  ;; We just need chez_ssh_ed25519_derive_pubkey. Let's assume it exists
  ;; (we'll add it to crypto.c).

  (define c-ed25519-derive-pubkey
    (foreign-procedure "chez_ssh_ed25519_derive_pubkey" (u8* u8*) int))

  ;; ---- Password authentication ----

  (define (ssh-auth-password ts username password)
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_USERAUTH_REQUEST
        (ssh-write-string username)
        (ssh-write-string "ssh-connection")
        (ssh-write-string "password")
        (ssh-write-boolean #f)  ;; not changing password
        (ssh-write-string password)))
    (handle-auth-response ts 'password))

  ;; ---- Keyboard-interactive authentication ----

  (define (ssh-auth-interactive ts username response-callback)
    ;; response-callback: (lambda (name instruction prompts) → list-of-responses)
    ;; prompts is list of (prompt-string . echo?)
    (ssh-transport-send-packet ts
      (ssh-make-payload SSH_MSG_USERAUTH_REQUEST
        (ssh-write-string username)
        (ssh-write-string "ssh-connection")
        (ssh-write-string "keyboard-interactive")
        (ssh-write-string "")    ;; language tag
        (ssh-write-string "")))  ;; submethods

    (let loop ()
      (let ([reply (ssh-transport-recv-packet ts)])
        (case (bytevector-u8-ref reply 0)
          [(52) #t]  ;; SSH_MSG_USERAUTH_SUCCESS
          [(51)      ;; SSH_MSG_USERAUTH_FAILURE
           (error 'ssh-auth-interactive "authentication failed")]
          [(60)      ;; SSH_MSG_USERAUTH_INFO_REQUEST
           ;; Parse info request
           (let* ([off 1]
                  [r1 (ssh-read-string reply off)]
                  [name (utf8->string (car r1))] [off (cdr r1)]
                  [r2 (ssh-read-string reply off)]
                  [instruction (utf8->string (car r2))] [off (cdr r2)]
                  [r3 (ssh-read-string reply off)]
                  [_lang (car r3)] [off (cdr r3)]
                  [r4 (ssh-read-uint32 reply off)]
                  [num-prompts (car r4)] [off (cdr r4)])
             (let prompt-loop ([i 0] [off off] [prompts '()])
               (if (>= i num-prompts)
                 (let* ([prompts (reverse prompts)]
                        [responses (response-callback name instruction prompts)])
                   ;; Send response
                   (let ([parts (map (lambda (r) (ssh-write-string r)) responses)])
                     (ssh-transport-send-packet ts
                       (apply ssh-make-payload SSH_MSG_USERAUTH_INFO_RESPONSE
                         (ssh-write-uint32 num-prompts)
                         parts)))
                   (loop))
                 (let* ([r (ssh-read-string reply off)]
                        [prompt-text (utf8->string (car r))] [off (cdr r)]
                        [r2 (ssh-read-boolean reply off)]
                        [echo? (car r2)] [off (cdr r2)])
                   (prompt-loop (+ i 1) off
                     (cons (cons prompt-text echo?) prompts))))))]
          [else
           (error 'ssh-auth-interactive "unexpected message"
                  (bytevector-u8-ref reply 0))]))))

  ;; ---- Response handler ----

  (define (handle-auth-response ts method)
    (let ([reply (ssh-transport-recv-packet ts)])
      (case (bytevector-u8-ref reply 0)
        [(52) #t]    ;; SSH_MSG_USERAUTH_SUCCESS
        [(51)        ;; SSH_MSG_USERAUTH_FAILURE
         (let* ([off 1]
                [r (ssh-read-name-list reply off)]
                [methods (car r)])
           (error 'ssh-auth (string-append (symbol->string method)
                              " authentication failed; try: "
                              (apply string-append
                                (let loop ([ms methods] [acc '()])
                                  (cond
                                    [(null? ms) (reverse acc)]
                                    [(null? (cdr ms)) (reverse (cons (car ms) acc))]
                                    [else (loop (cdr ms)
                                                (cons ", " (cons (car ms) acc)))]))))))]
        [else
         (error 'ssh-auth "unexpected response" (bytevector-u8-ref reply 0))])))

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
