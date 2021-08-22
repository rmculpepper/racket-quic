#lang racket/base
(require ffi/unsafe
         racket/random
         "ffi.rkt")

(define (tag-malloc tag . args)
  (define obj (apply malloc args))
  (cpointer-push-tag! obj tag)
  obj)

(define (new-ngtcp2_settings)
  (define settings (tag-malloc ngtcp2_settings-tag _ngtcp2_settings 'atomic-interior))
  (ngtcp2_settings_default settings)
  settings)

(define the-settings (new-ngtcp2_settings))

(define (new-ngtcp2_transport_params)
  (tag-malloc ngtcp2_transport_params-tag _ngtcp2_transport_params 'atomic-interior))

(define (new-client-ngtcp2_transport_params)
  (define tp (new-ngtcp2_transport_params))
  (ngtcp2_transport_params_default tp)
  tp)

(define the-transport-params (new-ngtcp2_transport_params))

(define (the-rand-cb buf buflen ctx)
  (memcpy buf (crypto-random-bytes buflen) buflen))

(define the-rand-cb-fpointer
  (cast the-rand-cb _ngtcp2_rand-function _ngtcp2_rand))

(define (the-new-cid-cb conn cid token cidlen user-data)
  (set-ngtcp2_cid-datalen! cid cidlen)
  (set-ngtcp2_cid-data! cid (crypto-random-bytes cidlen))
  (let ([tlen NGTCP2_STATELESS_RESET_TOKENLEN])
    (memcpy token (crypto-random-bytes tlen) tlen))
  0)

(define the-new-cid-cb-fpointer
  (cast the-new-cid-cb _ngtcp2_get_new_connection_id-function _ngtcp2_get_new_connection_id))

(define (new-ngtcp2_callbacks)
  (tag-malloc ngtcp2_callbacks-tag _ngtcp2_callbacks 'atomic-interior))

(define (new-client-ngtcp2_callbacks)
  (define cb (new-ngtcp2_callbacks))
  (set-ngtcp2_callbacks-client_initial! cb ngtcp2_crypto_client_initial_cb)
  (set-ngtcp2_callbacks-recv_crypto_data! cb ngtcp2_crypto_recv_crypto_data_cb)
  (set-ngtcp2_callbacks-encrypt! cb ngtcp2_crypto_encrypt_cb)
  (set-ngtcp2_callbacks-decrypt! cb ngtcp2_crypto_decrypt_cb)
  (set-ngtcp2_callbacks-hp_mask! cb ngtcp2_crypto_hp_mask_cb)
  (set-ngtcp2_callbacks-recv_retry! cb ngtcp2_crypto_recv_retry_cb)
  (set-ngtcp2_callbacks-rand! cb the-rand-cb-fpointer)
  (set-ngtcp2_callbacks-get_new_connection_id! cb #f)
  (set-ngtcp2_callbacks-update_key! cb ngtcp2_crypto_update_key_cb)
  (set-ngtcp2_callbacks-delete_crypto_aead_ctx! cb ngtcp2_crypto_delete_crypto_aead_ctx_cb)
  (set-ngtcp2_callbacks-delete_crypto_cipher_ctx! cb ngtcp2_crypto_delete_crypto_cipher_ctx_cb)
  (set-ngtcp2_callbacks-get_path_challenge_data! cb #f)
  cb)

(define (new-client-conn)
  (define dcid _)
  (define scid _)
  (define path _)
  (define version NGTCP2_PROTO_VER_MIN)
  (define cb (new-client-ngtcp2_callbacks))
  (define settings the-settings)
  (define params the-transport-params)
  (ngtcp2_conn_client_new dcid scid path version cb settings params #f))


(define (new-ip4-addr ip4 port)
  (make-ngtcp2_addr ? sa #f))

(define (new-ip6-addr ip6 port)
  (define sa _)
  (make-ngtcp2_addr ? sa #f))
