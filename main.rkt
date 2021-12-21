#lang racket/base
(require ffi/unsafe
         racket/random
         "ffi.rkt")

;; ============================================================
;; Settings

(define (new-ngtcp2_settings)
  (define settings (tag-malloc ngtcp2_settings-tag _ngtcp2_settings 'atomic-interior))
  (ngtcp2_settings_default settings)
  settings)

(define the-settings (new-ngtcp2_settings))

;; ============================================================
;; Transport Params

(define (new-ngtcp2_transport_params)
  (tag-malloc ngtcp2_transport_params-tag _ngtcp2_transport_params 'atomic-interior))

(define (new-client-ngtcp2_transport_params)
  (define tp (new-ngtcp2_transport_params))
  (ngtcp2_transport_params_default tp)
  tp)

(define the-transport-params (new-ngtcp2_transport_params))

;; ============================================================
;; CID

(define (new-cid-bytes [cidlen NGTCP2_MAX_CIDLEN])
  (crypto-random-bytes cidlen))

(define (new-cid [cidlen NGTCP2_MAX_CIDLEN])
  (define cid (tag-malloc ngtcp2_cid-tag _ngtcp2_cid))
  (ngtcp2_cid_init cid (new-cid-bytes cidlen))
  cid)

(define (new-stateless-reset-bytes cid-bytes)
  (define tlen NGTCP2_STATELESS_RESET_TOKENLEN)
  ;; FIXME: stateless reset token should be crypto-derived from CID
  (crypto-random-bytes tlen))

(define (the-new-cid-cb conn cid token cidlen user-data)
  (define cid-bytes (new-cid-bytes cidlen))
  (ngtcp2_cid_init cid cid-bytes)
  (let ([tlen NGTCP2_STATELESS_RESET_TOKENLEN])
    (memcpy token (new-stateless-reset-bytes cid-bytes) tlen))
  0)

(define the-new-cid-cb-fpointer
  (cast the-new-cid-cb _ngtcp2_get_new_connection_id-function _ngtcp2_get_new_connection_id))

;; ============================================================
;; Callbacks

(define (the-rand-cb buf buflen ctx)
  (memcpy buf (crypto-random-bytes buflen) buflen))

(define the-rand-cb-fpointer
  (cast the-rand-cb _ngtcp2_rand-function _ngtcp2_rand))

(define (new-ngtcp2_callbacks)
  (tag-malloc ngtcp2_callbacks-tag _ngtcp2_callbacks 'atomic-interior))

(define (init-callbacks cb)
  (set-ngtcp2_callbacks-recv_crypto_data! cb ngtcp2_crypto_recv_crypto_data_cb)
  (set-ngtcp2_callbacks-encrypt! cb ngtcp2_crypto_encrypt_cb)
  (set-ngtcp2_callbacks-decrypt! cb ngtcp2_crypto_decrypt_cb)
  (set-ngtcp2_callbacks-hp_mask! cb ngtcp2_crypto_hp_mask_cb)
  (set-ngtcp2_callbacks-rand! cb the-rand-cb-fpointer)
  (set-ngtcp2_callbacks-update_key! cb ngtcp2_crypto_update_key_cb)
  (set-ngtcp2_callbacks-delete_crypto_aead_ctx! cb ngtcp2_crypto_delete_crypto_aead_ctx_cb)
  (set-ngtcp2_callbacks-delete_crypto_cipher_ctx! cb ngtcp2_crypto_delete_crypto_cipher_ctx_cb)
  (set-ngtcp2_callbacks-get_path_challenge_data! cb ngtcp2_crypto_get_path_challenge_data_cb)
  (void))

(define (new-client-ngtcp2_callbacks)
  (define cb (new-ngtcp2_callbacks))
  (init-callbacks cb)
  (set-ngtcp2_callbacks-client_initial! cb ngtcp2_crypto_client_initial_cb)
  (set-ngtcp2_callbacks-recv_retry! cb ngtcp2_crypto_recv_retry_cb)
  (set-ngtcp2_callbacks-get_new_connection_id! cb the-new-cid-cb-fpointer)
  cb)

(define (new-server-ngtcp2_callbacks)
  (define cb (new-ngtcp2_callbacks))
  (init-callbacks cb)
  (set-ngtcp2_callbacks-recv_client_initial! cb ngtcp2_crypto_recv_client_initial_cb)
  (set-ngtcp2_callbacks-get_new_connection_id! cb the-new-cid-cb-fpointer)
  cb)

;; ============================================================
;; Addresses and Paths

;; FIXME: Linux-specific

(define AF_INET 2)
(define AF_INET6 10)

(define _sa_family _ushort)
(define _in_port _uint16)
(define _in_addr _uint32)

(define-cstruct _sockaddr_in
  ([sa_family _sa_family] ;; = AF_INET4
   [sin_port _in_port]
   [sin_addr _in_addr])
  #:malloc-mode 'raw)

(define _in6_addr (_array/list _uint16 8))

(define-cstruct _sockaddr_in6
  ([sa_family _sa_family] ;; = AF_INET6
   [sin6_port _in_port]
   [sin6_flowinfo _uint32]
   [sin6_addr _in6_addr]
   [sin6_scope_id _uint32])
  #:malloc-mode 'raw)

(define (new-ip4-addr ip4 port)
  (make-ngtcp2_addr (ctype-sizeof _sockaddr_in)
                    (make-sockaddr_in AF_INET port ip4)))

(define (new-ip6-addr ip6 port)
  (define sa (tag-malloc sockaddr_in6-tag _sockaddr_in6 'raw))
  (make-ngtcp2_addr (ctype-sizeof _sockaddr_in6)
                    (make-sockaddr_in6 AF_INET6 port 0 (ip6-decompose-number ip6) 0)))

(define (string->addr addr port)
  (cond [(ip4-addr? addr)
         (new-ip4-addr (string->ip4 addr) port)]
        [(ip6-addr? addr)
         (new-ip6-addr (string->ip6 addr) port)]
        [else (error 'string->addr "bad address: ~e" addr)]))

;; ============================================================
;; Client connection

(require racket/udp
         racket/class
         "addr.rkt")

(define (new-client-conn path)
  (define dcid (new-cid))
  (define scid (new-cid))
  (define version NGTCP2_PROTO_VER_MIN)
  (define cb (new-client-ngtcp2_callbacks))
  (define settings the-settings)
  (define params the-transport-params)
  (ngtcp2_conn_client_new dcid scid path version cb settings params #f))

(define (new-client peer-host peer-port)
  (define sock (udp-open-socket peer-host peer-port))
  (udp-bind! sock #f 0)
  (udp-connect! sock peer-host peer-port)
  (define-values (my-addr my-port peer-addr _peer-port)
    (udp-addresses sock #t))
  (define path
    (make-ngtcp2_path (string->addr my-addr my-port)
                      (string->addr peer-addr peer-port)
                      #f))
  (define conn (new-client-conn path))
  (new client% (sock sock) (path path) (conn conn)))

(define client%
  (class object%
    (init-field sock
                path
                conn)
    (super-new)

    (define buflen 1200)
    (define buf (make-bytes buflen 0))

    (define/public (go1)
      (define len (ngtcp2_conn_write_pkt conn path #f buf buflen (now)))
      (unless (> len 0)
        (error 'go "len = ~s" len))
      (udp-send* sock buf 0 len))

    (define/public (go2)
      (define-values (len sender-addr sender-port) (udp-receive! sock recv-buf))
      

    (define/public (now)
      (define ns (* (current-inexact-milliseconds) NGTCP2_MILLISECONDS))
      (inexact->exact (truncate ns)))
    ))
