#lang racket/base
(require ffi/unsafe
         ffi/unsafe/define)
(provide (protect-out (all-defined-out)))

;; ============================================================

(define-ffi-definer define-ng
  (ffi-lib "libngtcp2" '("0" #f)#:fail (lambda () #f))
  #:default-make-fail make-not-available)

(define-ffi-definer define-ngc
  (ffi-lib "libngtcp2_crypto_openssl" '("0" #f) #:fail (lambda () #f))
  #:default-make-fail make-not-available)

;; ============================================================

(define _ngtcp2_ssize _ptrdiff)

(define _ngtcp2_mem* _pointer)

;; Time is measured in nanoseconds.
(define NGTCP2_SECONDS 1000000000)
(define NGTCP2_MILLISECONDS 1000000)
(define NGTCP2_MICROSECONDS 1000)
(define NGTCP2_NANOSECONDS 1)

(define NGTCP2_PROTO_VER_V1 #x00000001)
(define NGTCP2_PROTO_VER_DRAFT_MAX #xff000020)
(define NGTCP2_PROTO_VER_DRAFT_MIN #xff00001d)
(define NGTCP2_PROTO_VER_MAX NGTCP2_PROTO_VER_V1)
(define NGTCP2_PROTO_VER_MIN NGTCP2_PROTO_VER_DRAFT_MIN)

(define NGTCP2_MAX_PKTLEN_IPV4 1252)
(define NGTCP2_MAX_PKTLEN_IPV6 1232)
(define NGTCP2_MIN_INITIAL_PKTLEN 1200)
(define NGTCP2_DEFAULT_MAX_PKTLEN 1200)

(define NGTCP2_MAX_VARINT (sub1 (expt 2 62)))
(define NGTCP2_STATELESS_RESET_TOKENLEN 16)
(define NGTCP2_MIN_STATELESS_RESET_RANDLEN 5)
(define NGTCP2_PATH_CHALLENGE_DATALEN 8)

(define NGTCP2_RETRY_KEY_DRAFT
  #"\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1")

(define NGTCP2_RETRY_NONCE_DRAFT
  #"\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c")

(define NGTCP2_RETRY_KEY_V1
  #"\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e")

(define NGTCP2_RETRY_NONCE_V1
  #"\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb")

(define NGTCP2_HP_MASKLEN 5)
(define NGTCP2_HP_SAMPLELEN 16)

(define NGTCP2_DEFAULT_INITIAL_RTT (* 333 NGTCP2_MILLISECONDS))

(define NGTCP2_MAX_CIDLEN 20)
(define NGTCP2_MIN_CIDLEN 1)
(define NGTCP2_MIN_INITIAL_DCIDLEN 8)

(define NGTCP2_ECN_NOT_ECT #x0)
(define NGTCP2_ECN_ECT_1 #x1)
(define NGTCP2_ECN_ECT_0 #x2)
(define NGTCP2_ECN_CE #x3)
(define NGTCP2_ECN_MASK #x3)

(define-cstruct _ngtcp2_pkt_info
  ([ecn _uint32]))
(define _ngtcp2_pkt_info* _ngtcp2_pkt_info-pointer/null)

(define NGTCP2_ERR_INVALID_ARGUMENT -201)
(define NGTCP2_ERR_NOBUF -203)
(define NGTCP2_ERR_PROTO -205)
(define NGTCP2_ERR_INVALID_STATE -206)
(define NGTCP2_ERR_ACK_FRAME -207)
(define NGTCP2_ERR_STREAM_ID_BLOCKED -208)
(define NGTCP2_ERR_STREAM_IN_USE -209)
(define NGTCP2_ERR_STREAM_DATA_BLOCKED -210)
(define NGTCP2_ERR_FLOW_CONTROL -211)
(define NGTCP2_ERR_CONNECTION_ID_LIMIT -212)
(define NGTCP2_ERR_STREAM_LIMIT -213)
(define NGTCP2_ERR_FINAL_SIZE -214)
(define NGTCP2_ERR_CRYPTO -215)
(define NGTCP2_ERR_PKT_NUM_EXHAUSTED -216)
(define NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM -217)
(define NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM -218)
(define NGTCP2_ERR_FRAME_ENCODING -219)
(define NGTCP2_ERR_TLS_DECRYPT -220)
(define NGTCP2_ERR_STREAM_SHUT_WR -221)
(define NGTCP2_ERR_STREAM_NOT_FOUND -222)
(define NGTCP2_ERR_STREAM_STATE -226)
(define NGTCP2_ERR_RECV_VERSION_NEGOTIATION -229)
(define NGTCP2_ERR_CLOSING -230)
(define NGTCP2_ERR_DRAINING -231)
(define NGTCP2_ERR_TRANSPORT_PARAM -234)
(define NGTCP2_ERR_DISCARD_PKT -235)
(define NGTCP2_ERR_PATH_VALIDATION_FAILED -236)
(define NGTCP2_ERR_CONN_ID_BLOCKED -237)
(define NGTCP2_ERR_INTERNAL -238)
(define NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED -239)
(define NGTCP2_ERR_WRITE_MORE -240)
(define NGTCP2_ERR_RETRY -241)
(define NGTCP2_ERR_DROP_CONN -242)
(define NGTCP2_ERR_AEAD_LIMIT_REACHED -243)
(define NGTCP2_ERR_NO_VIABLE_PATH -244)
(define NGTCP2_ERR_FATAL -500)
(define NGTCP2_ERR_NOMEM -501)
(define NGTCP2_ERR_CALLBACK_FAILURE -502)

(define NGTCP2_PKT_FLAG_NONE 0)
(define NGTCP2_PKT_FLAG_LONG_FORM #x01)
(define NGTCP2_PKT_FLAG_KEY_PHASE #x04)

;; (define _ngtcp2_pkt_type _int) ;; enum
;; (define NGTCP2_PKT_VERSION_NEGOTIATION #xf0)
;; (define NGTCP2_PKT_INITIAL #x0)
;; (define NGTCP2_PKT_0RTT #x1)
;; (define NGTCP2_PKT_HANDSHAKE #x2)
;; (define NGTCP2_PKT_RETRY #x3)
;; (define NGTCP2_PKT_SHORT #x70)
(define _ngtcp2_pkt_type
  (_enum '(version_negotiation = #xf0
           initial = #x0
           0rtt = #x1
           handshake = #x2
           retry = #x3
           short = #x70)))

(define NGTCP2_NO_ERROR #x0)
(define NGTCP2_INTERNAL_ERROR #x1)
(define NGTCP2_CONNECTION_REFUSED #x2)
(define NGTCP2_FLOW_CONTROL_ERROR #x3)
(define NGTCP2_STREAM_LIMIT_ERROR #x4)
(define NGTCP2_STREAM_STATE_ERROR #x5)
(define NGTCP2_FINAL_SIZE_ERROR #x6)
(define NGTCP2_FRAME_ENCODING_ERROR #x7)
(define NGTCP2_TRANSPORT_PARAMETER_ERROR #x8)
(define NGTCP2_CONNECTION_ID_LIMIT_ERROR #x9)
(define NGTCP2_PROTOCOL_VIOLATION #xa)
(define NGTCP2_INVALID_TOKEN #xb)
(define NGTCP2_APPLICATION_ERROR #xc)
(define NGTCP2_CRYPTO_BUFFER_EXCEEDED #xd)
(define NGTCP2_KEY_UPDATE_ERROR #xe)
(define NGTCP2_AEAD_LIMIT_REACHED #xf)
(define NGTCP2_NO_VIABLE_PATH #x10)
(define NGTCP2_CRYPTO_ERROR #x100)

(define _ngtcp_path_validation_result
  (_enum '(success failure aborted)))

(define _ngtcp2_tstamp _uint64)
(define _ngtcp2_duration _uint64)

(define-cstruct _ngtcp2_cid
  ([datalen _size]
   [data (_array _byte NGTCP2_MAX_CIDLEN)]))
(define _ngtcp2_cid* _ngtcp2_cid-pointer/null)

(define-cstruct _ngtcp2_vec
  ([base _pointer]
   [len _size]))
(define _ngtcp2_vec* _ngtcp2_vec-pointer/null)

(define-ng ngtcp2_cid_init
  (_fun (cid data) ::
        (cid : _ngtcp2_cid*)
        (data : _bytes)
        (_size = (bytes-length data))
        -> _void))

(define-cstruct _ngtcp2_pkt_hd
  ([dcid _ngtcp2_cid]
   [scid _ngtcp2_cid]
   [pkt_num _int64]
   [token _ngtcp2_vec]
   [pkg_numlen _size]
   [len _size]
   [version _uint32]
   [type _uint8]
   [flags _uint8]))
(define _ngtcp2_pkt_hd* _ngtcp2_pkt_hd-pointer/null)

(define-cstruct _ngtcp2_pkt_stateless_reset
  ([stateless_reset_token (_array _byte NGTCP2_STATELESS_RESET_TOKENLEN)]
   [rand _pointer]
   [randlen _size]))

(define _ngtcp2_transport_param_id
  (_enum '(original_destination_connection_id = #x0000
           max_idle_timeout = #x0001
           stateless_reset_token = #x0002
           max_udp_payload_size = #x0003
           initial_max_data = #x0004
           initial_max_stream_data_bidi_local = #x0005
           initial_max_stream_data_bidi_remote = #x0006
           initial_max_stream_data_uni = #x0007
           initial_max_streams_bidi = #x0008
           initial_max_streams_uni = #x0009
           ack_delay_exponent = #x000a
           max_ack_delay = #x000b
           disable_active_migration = #x000c
           preferred_address = #x000d
           active_connection_id_limit = #x000e
           initial_source_connection_id = #x000f
           retry_source_connection_id = #x0010
           max_datagram_frame_size = #x0020)))

(define _ngtcp2_transport_params_type
  (_enum '(hello encrypted_extensions)))

(define NGTCP2_DEFAULT_MAX_UDP_PAYLOAD_SIZE 65527)
(define NGTCP2_DEFAULT_ACK_DELAY_EXPONENT 3)
(define NGTCP2_DEFAULT_MAX_ACK_DELAY (* 25 NGTCP2_MILLISECONDS))
(define NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT 2)
(define NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1 #x39)
(define NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_DRAFT #xffa5)

(define-cstruct _ngtcp2_preferred_addr
  ([cid _ngtcp2_cid]
   [ipv4_port _uint16]
   [ipv6_port _uint16]
   [ipv4_addr (_array _byte 4)]
   [ipv6_addr (_array _byte 16)]
   [ipv4_present _uint8]
   [ipv6_present _uint8]
   [stateless_reset_token (_array _byte NGTCP2_STATELESS_RESET_TOKENLEN)]))

(define-cstruct _ngtcp2_transport_params
  ([preferred_address _ngtcp2_preferred_addr]
   [original_dcid _ngtcp2_cid]
   [initial_scid _ngtcp2_cid]
   [retry_scid _ngtcp2_cid]
   [initial_max_stream_data_bidi_local _uint64]
   [initial_max_stream_data_bidi_remote _uint64]
   [initial_max_stream_data_uni _uint64]
   [initial_max_data _uint64]
   [initial_max_streams_bidi _uint64]
   [initial_max_streams_uni _uint64]
   [max_idle_timeout _ngtcp2_duration]
   [max_udp_payload_size _uint64]
   [active_connection_id_limit _uint64]
   [ack_delay_exponent _uint64]
   [max_ack_delay _ngtcp2_duration]
   [max_datagram_frame_size _uint64]
   [stateless_reset_token_present _uint8]
   [disable_active_migration _uint8]
   [retry_scid_present _uint8]
   [preferred_address_present _uint8]
   [stateless_reset_token (_array _byte NGTCP2_STATELESS_RESET_TOKENLEN)]))
(define _ngtcp2_transport_params* _ngtcp2_transport_params-pointer/null)

(define-cpointer-type _ngtcp2_log*)

(define _ngtcp2_pktns_id
  (_enum '(initial handshake application max)))
(define NGTCP2_PKTNS_ID_MAX 3)

(define-cstruct _ngtcp2_conn_stat
  ([latest_rtt _ngtcp2_duration]
   [min_rtt _ngtcp2_duration]
   [smoothed_rtt _ngtcp2_duration]
   [rttvar _ngtcp2_duration]
   [initial_rtt _ngtcp2_duration]
   [first_rtt_sample_ts _ngtcp2_tstamp]
   [pto_count _size]
   [loss_detection_timer _ngtcp2_tstamp]
   [last_tx_pkt_ts (_array _ngtcp2_tstamp NGTCP2_PKTNS_ID_MAX)]
   [loss_time _ngtcp2_tstamp]
   [cwnd _uint64]
   [ssthresh _uint64]
   [congestion_recovery_start_ts _ngtcp2_tstamp]
   [bytes_in_flight _uint64]
   [max_udp_payload_size _size]
   [delivery_rate_sec _uint64]
   [pacing_rate _double]
   [send_quantum _size]))
(define _ngtcp2_conn_stat* _ngtcp2_conn_stat-pointer/null)

(define _ngtcp2_cc_algo
  (_enum '(reno cubic bbr custom = #xff)))

#|
/**
 * @struct
 *
 * :type:`ngtcp2_cc_base` is the base structure of custom congestion
 * control algorithm.  It must be the first field of custom congestion
 * controller.
 */
typedef struct ngtcp2_cc_base {
  /**
   * :member:`log` is ngtcp2 library internal logger.
   */
  ngtcp2_log *log;
} ngtcp2_cc_base;

/**
 * @struct
 *
 * :type:`ngtcp2_cc_pkt` is a convenient structure to include
 * acked/lost/sent packet.
 */
typedef struct ngtcp2_cc_pkt {
  /**
   * :member:`pkt_num` is the packet number
   */
  int64_t pkt_num;
  /**
   * :member:`pktlen` is the length of packet.
   */
  size_t pktlen;
  /**
   * :member:`pktns_id` is the ID of packet number space which this
   * packet belongs to.
   */
  ngtcp2_pktns_id pktns_id;
  /**
   * :member:`sent_ts` is the timestamp when packet is sent.
   */
  ngtcp2_tstamp sent_ts;
} ngtcp2_cc_pkt;

/**
 * @struct
 *
 * :type:`ngtcp2_cc_ack` is a convenient structure which stores
 * acknowledged and lost bytes.
 */
typedef struct ngtcp2_cc_ack {
  /**
   * :member:`prior_bytes_in_flight` is the in-flight bytes before
   * processing this ACK.
   */
  uint64_t prior_bytes_in_flight;
  /**
   * :member:`bytes_delivered` is the number of bytes acknowledged.
   */
  uint64_t bytes_delivered;
  /**
   * :member:`bytes_lost` is the number of bytes declared lost.
   */
  uint64_t bytes_lost;
  /**
   * :member:`pkt_delivered` is the cumulative acknowledged bytes when
   * the last packet acknowledged by this ACK was sent.
   */
  uint64_t pkt_delivered;
  /**
   * :member:`largest_acked_sent_ts` is the time when the largest
   * acknowledged packet was sent.
   */
  ngtcp2_tstamp largest_acked_sent_ts;
} ngtcp2_cc_ack;

typedef struct ngtcp2_cc ngtcp2_cc;
|#

(define _ngtcp2_cc_on_pkt_acked* _fpointer)
(define _ngtcp2_cc_congestion_event* _fpointer)
(define _ngtcp2_cc_on_spurious_congestion* _fpointer)
(define _ngtcp2_cc_on_persistent_congestion* _fpointer)
(define _ngtcp2_cc_on_ack_recv* _fpointer)
(define _ngtcp2_cc_on_pkt_sent* _fpointer)
(define _ngtcp2_cc_new_rtt_sample* _fpointer)
(define _ngtcp2_cc_reset* _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_on_pkt_acked` is a callback function which is
 * called with an acknowledged packet.
 */
typedef void (*ngtcp2_cc_on_pkt_acked)(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                       const ngtcp2_cc_pkt *pkt,
                                       ngtcp2_tstamp ts);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_congestion_event` is a callback function which is
 * called when congestion event happens (e.g., when packet is lost).
 */
typedef void (*ngtcp2_cc_congestion_event)(ngtcp2_cc *cc,
                                           ngtcp2_conn_stat *cstat,
                                           ngtcp2_tstamp sent_ts,
                                           ngtcp2_tstamp ts);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_on_spurious_congestion` is a callback function
 * which is called when a spurious congestion is detected.
 */
typedef void (*ngtcp2_cc_on_spurious_congestion)(ngtcp2_cc *cc,
                                                 ngtcp2_conn_stat *cstat,
                                                 ngtcp2_tstamp ts);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_on_persistent_congestion` is a callback function
 * which is called when persistent congestion is established.
 */
typedef void (*ngtcp2_cc_on_persistent_congestion)(ngtcp2_cc *cc,
                                                   ngtcp2_conn_stat *cstat,
                                                   ngtcp2_tstamp ts);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_on_ack_recv` is a callback function which is
 * called when an acknowledgement is received.
 */
typedef void (*ngtcp2_cc_on_ack_recv)(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                      const ngtcp2_cc_ack *ack,
                                      ngtcp2_tstamp ts);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_on_pkt_sent` is a callback function which is
 * called when an ack-eliciting packet is sent.
 */
typedef void (*ngtcp2_cc_on_pkt_sent)(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                      const ngtcp2_cc_pkt *pkt);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_new_rtt_sample` is a callback function which is
 * called when new RTT sample is obtained.
 */
typedef void (*ngtcp2_cc_new_rtt_sample)(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                         ngtcp2_tstamp ts);

/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_reset` is a callback function which is called when
 * congestion state must be reset.
 */
typedef void (*ngtcp2_cc_reset)(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                ngtcp2_tstamp ts);
|#

(define _ngtcp2_cc_event_type
  (_enum '(tx_start)))

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_cc_event` is a callback function which is called when
 * a specific event happens.
 */
typedef void (*ngtcp2_cc_event)(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                ngtcp2_cc_event_type event, ngtcp2_tstamp ts);
|#
(define _ngtcp2_cc_event _fpointer)

#|
/**
 * @struct
 *
 * :type:`ngtcp2_cc` is congestion control algorithm interface to
 * allow custom implementation.
 */
typedef struct ngtcp2_cc {
  /**
   * :member:`ccb` is a pointer to :type:`ngtcp2_cc_base` which
   * usually contains a state.
   */
  ngtcp2_cc_base *ccb;
  /**
   * :member:`on_pkt_acked` is a callback function which is called
   * when a packet is acknowledged.
   */
  ngtcp2_cc_on_pkt_acked on_pkt_acked;
  /**
   * :member:`congestion_event` is a callback function which is called
   * when congestion event happens (.e.g, packet is lost).
   */
  ngtcp2_cc_congestion_event congestion_event;
  /**
   * :member:`on_spurious_congestion` is a callback function which is
   * called when a spurious congestion is detected.
   */
  ngtcp2_cc_on_spurious_congestion on_spurious_congestion;
  /**
   * :member:`on_persistent_congestion` is a callback function which
   * is called when persistent congestion is established.
   */
  ngtcp2_cc_on_persistent_congestion on_persistent_congestion;
  /**
   * :member:`on_ack_recv` is a callback function which is called when
   * an acknowledgement is received.
   */
  ngtcp2_cc_on_ack_recv on_ack_recv;
  /**
   * :member:`on_pkt_sent` is a callback function which is called when
   * ack-eliciting packet is sent.
   */
  ngtcp2_cc_on_pkt_sent on_pkt_sent;
  /**
   * :member:`new_rtt_sample` is a callback function which is called
   * when new RTT sample is obtained.
   */
  ngtcp2_cc_new_rtt_sample new_rtt_sample;
  /**
   * :member:`reset` is a callback function which is called when
   * congestion control state must be reset.
   */
  ngtcp2_cc_reset reset;
  /**
   * :member:`event` is a callback function which is called when a
   * specific event happens.
   */
  ngtcp2_cc_event event;
} ngtcp2_cc;
|#
(define _ngtcp2_cc* _pointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_printf` is a callback function for logging.
 * |user_data| is the same object passed to `ngtcp2_conn_client_new`
 * or `ngtcp2_conn_server_new`.
 */
typedef void (*ngtcp2_printf)(void *user_data, const char *format, ...);
|#
(define _ngtcp2_printf _fpointer)

(define NGTCP2_QLOG_WRITE_FLAG_NONE 0)
(define NGTCP2_QLOG_WRITE_FLAG_FIN #x01)

(define _ngtcp2_rand_ctx _pointer) ;; actually struct {void*}
(define _ngtcp2_rand_ctx* _pointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_qlog_write` is a callback function which is called to
 * write qlog |data| of length |datalen| bytes.  |flags| is bitwise OR
 * of zero or more of NGTCP2_QLOG_WRITE_FLAG_*.  See
 * :macro:`NGTCP2_QLOG_WRITE_FLAG_NONE`.  If
 * :macro:`NGTCP2_QLOG_WRITE_FLAG_FIN` is set, |datalen| may be 0.
 */
typedef void (*ngtcp2_qlog_write)(void *user_data, uint32_t flags,
                                  const void *data, size_t datalen);
|#
(define _ngtcp2_qlog_write _fpointer)

(define-cstruct _ngtcp2_qlog_settings
  ([odcid _ngtcp2_cid] ;; ignored?
   [write _ngtcp2_qlog_write] ;; NULL
   ))

(define-cstruct _ngtcp2_settings
  ([qlog _ngtcp2_qlog_settings]
   [cc_algo _ngtcp2_cc_algo]
   [cc _ngtcp2_cc*] ;; NULL
   [initial_ts _ngtcp2_tstamp]
   [initial_rtt _ngtcp2_duration]
   [log_printf _ngtcp2_printf] ;; NULL
   [max_udp_payload_size _size]
   [token _ngtcp2_vec]
   [rand_ctx _ngtcp2_rand_ctx] ;; NULL
   [max_window _uint64]
   [max_stream_window _uint64]
   [ack_thresh _size]))
(define _ngtcp2_settings* _ngtcp2_settings-pointer/null)

(define _sockaddr* _pointer) ;; FIXME

(define SOCKADDR_STORAGE_SIZE 128) ;; FIXME! FIXME alignment!
(define _sockaddr_storage (_array _byte SOCKADDR_STORAGE_SIZE))

(define-cstruct _ngtcp2_addr
  ([addrlen _size]
   [addr _sockaddr*]))
(define _ngtcp2_addr* _ngtcp2_addr-pointer/null)

(define-cstruct _ngtcp2_path
  ([local _ngtcp2_addr]
   [remote _ngtcp2_addr]
   [user_data _pointer]))
(define _ngtcp2_path* _ngtcp2_path-pointer/null)

(define-cstruct _ngtcp2_path_storage
  ([local_addrbuf _sockaddr_storage]
   [remote_addrbuf _sockaddr_storage]
   [path _ngtcp2_path]))
(define _ngtcp2_path_storage* _ngtcp2_path_storage-pointer/null)

(define _ngtcp2_crypto_md _pointer) ;; actually, struct {void*}
(define _ngtcp2_crypto_md* _pointer)

(define-cstruct _ngtcp2_crypto_aead
  ([native_handle _pointer]
   [max_overhead _size]))
(define _ngtcp2_crypto_aead* _ngtcp2_crypto_aead-pointer/null)

(define _ngtcp2_crypto_cipher _pointer) ;; actually, struct {void*}
(define _ngtcp2_crypto_cipher* _pointer)

(define _ngtcp2_crypto_aead_ctx _pointer) ;; actually, struct {void*}
(define _ngtcp2_crypto_aead_ctx* _pointer)

(define _ngtcp2_crypto_cipher_ctx _pointer) ;; actually, struct {void*}
(define _ngtcp2_crypto_cipher_ctx* _pointer)

(define-cstruct _ngtcp2_crypto_ctx
  ([aead _ngtcp2_crypto_aead]
   [md _ngtcp2_crypto_md]
   [hp _ngtcp2_crypto_cipher]
   [max_encryption _uint64]
   [max_decryption_failure _uint64]))
(define _ngtcp2_crypto_ctx* _ngtcp2_crypto_ctx-pointer/null)

(define-ng ngtcp2_encode_transport_params
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [exttype : _ngtcp2_transport_params_type]
        [params : #;const _ngtcp2_transport_params*]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_decode_transport_params
  (_fun [prams : _ngtcp2_transport_params*]
        [exttype : _ngtcp2_transport_params_type]
        [data : #;const _bytes]
        [datalen : _size = (bytes-length data)]
        -> _int))

#|
/**
 * @function
 *
 * `ngtcp2_pkt_decode_version_cid` extracts QUIC version, Destination
 * Connection ID and Source Connection ID from the packet pointed by
 * |data| of length |datalen|.  This function can handle Connection ID
 * up to 255 bytes unlike `ngtcp2_pkt_decode_hd_long` or
 * `ngtcp2_pkt_decode_hd_short` which are only capable of handling
 * Connection ID less than or equal to :macro:`NGTCP2_MAX_CIDLEN`.
 * Longer Connection ID is only valid if the version is unsupported
 * QUIC version.
 *
 * If the given packet is Long packet, this function extracts the
 * version from the packet and assigns it to |*pversion|.  It also
 * extracts the pointer to the Destination Connection ID and its
 * length and assigns them to |*pdcid| and |*pdcidlen| respectively.
 * Similarly, it extracts the pointer to the Source Connection ID and
 * its length and assigns them to |*pscid| and |*pscidlen|
 * respectively.
 *
 * If the given packet is Short packet, |*pversion| will be 0,
 * |*pscid| will be ``NULL``, and |*pscidlen| will be 0.  Because the
 * Short packet does not have the length of Destination Connection ID,
 * the caller has to pass the length in |short_dcidlen|.  This
 * function extracts the pointer to the Destination Connection ID and
 * assigns it to |*pdcid|.  |short_dcidlen| is assigned to
 * |*pdcidlen|.
 *
 * This function returns 0 or 1 if it succeeds.  It returns 1 if
 * Version Negotiation packet should be sent.  Otherwise, one of the
 * following negative error code:
 *
 * :macro:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     The function could not decode the packet header.
 */
int
ngtcp2_pkt_decode_version_cid(uint32_t *pversion, const uint8_t **pdcid,
                              size_t *pdcidlen, const uint8_t **pscid,
                              size_t *pscidlen, const uint8_t *data,
                              size_t datalen, size_t short_dcidlen);

/**
 * @function
 *
 * `ngtcp2_pkt_decode_hd_long` decodes QUIC long packet header in
 * |pkt| of length |pktlen|.  This function only parses the input just
 * before packet number field.
 *
 * This function does not verify that length field is correct.  In
 * other words, this function succeeds even if length > |pktlen|.
 *
 * This function can handle Connection ID up to
 * :macro:`NGTCP2_MAX_CIDLEN`.  Consider to use
 * `ngtcp2_pkt_decode_version_cid` to get longer Connection ID.
 *
 * This function handles Version Negotiation specially.  If version
 * field is 0, |pkt| must contain Version Negotiation packet.  Version
 * Negotiation packet has random type in wire format.  For
 * convenience, this function sets
 * :enum:`ngtcp2_pkt_type.NGTCP2_PKT_VERSION_NEGOTIATION` to
 * :member:`dest->type <ngtcp2_pkt_hd.type>`, and sets 0 to
 * :member:`dest->len <ngtcp2_pkt_hd.len>`.  Version Negotiation
 * packet occupies a single packet.
 *
 * It stores the result in the object pointed by |dest|, and returns
 * the number of bytes decoded to read the packet header if it
 * succeeds, or one of the following error codes:
 *
 * :macro:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     Packet is too short; or it is not a long header
 */
ngtcp2_ssize ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest,
                                                     const uint8_t *pkt,
                                                     size_t pktlen);

/**
 * @function
 *
 * `ngtcp2_pkt_decode_hd_short` decodes QUIC short packet header in
 * |pkt| of length |pktlen|.  |dcidlen| is the length of DCID in
 * packet header.  Short packet does not encode the length of
 * connection ID, thus we need the input from the outside.  This
 * function only parses the input just before packet number field.
 * This function can handle Connection ID up to
 * :macro:`NGTCP2_MAX_CIDLEN`.  Consider to use
 * `ngtcp2_pkt_decode_version_cid` to get longer Connection ID.  It
 * stores the result in the object pointed by |dest|, and returns the
 * number of bytes decoded to read the packet header if it succeeds,
 * or one of the following error codes:
 *
 * :macro:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     Packet is too short; or it is not a short header
 */
ngtcp2_ssize ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest,
                                                      const uint8_t *pkt,
                                                      size_t pktlen,
                                                      size_t dcidlen);

/**
 * @function
 *
 * `ngtcp2_pkt_write_stateless_reset` writes Stateless Reset packet in
 * the buffer pointed by |dest| whose length is |destlen|.
 * |stateless_reset_token| is a pointer to the Stateless Reset Token,
 * and its length must be :macro:`NGTCP2_STATELESS_RESET_TOKENLEN`
 * bytes long.  |rand| specifies the random octets preceding Stateless
 * Reset Token.  The length of |rand| is specified by |randlen| which
 * must be at least :macro:`NGTCP2_MIN_STATELESS_RETRY_RANDLEN` bytes
 * long.
 *
 * If |randlen| is too long to write them all in the buffer, |rand| is
 * written to the buffer as much as possible, and is truncated.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :macro:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 * :macro:`NGTCP2_ERR_INVALID_ARGUMENT`
 *     |randlen| is strictly less than
 *     :macro:`NGTCP2_MIN_STATELESS_RETRY_RANDLEN`.
 */
ngtcp2_ssize ngtcp2_pkt_write_stateless_reset(
    uint8_t *dest, size_t destlen, const uint8_t *stateless_reset_token,
    const uint8_t *rand, size_t randlen);

/**
 * @function
 *
 * `ngtcp2_pkt_write_version_negotiation` writes Version Negotiation
 * packet in the buffer pointed by |dest| whose length is |destlen|.
 * |unused_random| should be generated randomly.  |dcid| is the
 * destination connection ID which appears in a packet as a source
 * connection ID sent by client which caused version negotiation.
 * Similarly, |scid| is the source connection ID which appears in a
 * packet as a destination connection ID sent by client.  |sv| is a
 * list of supported versions, and |nsv| specifies the number of
 * supported versions included in |sv|.
 *
 * This function returns the number of bytes written to the buffer, or
 * one of the following negative error codes:
 *
 * :macro:`NGTCP2_ERR_NOBUF`
 *     Buffer is too small.
 */
ngtcp2_ssize ngtcp2_pkt_write_version_negotiation(
    uint8_t *dest, size_t destlen, uint8_t unused_random, const uint8_t *dcid,
    size_t dcidlen, const uint8_t *scid, size_t scidlen, const uint32_t *sv,
    size_t nsv);
|#

(define _ngtcp2_conn* _pointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_client_initial` is invoked when client application
 * asks TLS stack to produce first TLS cryptographic handshake data.
 *
 * This implementation of this callback must get the first handshake
 * data from TLS stack and pass it to ngtcp2 library using
 * `ngtcp2_conn_submit_crypto_data` function.  Make sure that before
 * calling `ngtcp2_conn_submit_crypto_data` function, client
 * application must create initial packet protection keys and IVs, and
 * provide them to ngtcp2 library using `ngtcp2_conn_set_initial_key`
 * and
 *
 * This callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * NGTCP2_ERR_CRYPTO.
 */
typedef int (*ngtcp2_client_initial)(ngtcp2_conn *conn, void *user_data);
|#
(define _ngtcp2_client_initial _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_client_initial` is invoked when server receives
 * Initial packet from client.  An server application must implement
 * this callback, and generate initial keys and IVs for both
 * transmission and reception.  Install them using
 * `ngtcp2_conn_set_initial_key`.  |dcid| is the destination
 * connection ID which client generated randomly.  It is used to
 * derive initial packet protection keys.
 *
 * The callback function must return 0 if it succeeds.  If an error
 * occurs, return :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the
 * library call return immediately.
 *
 * TODO: Define error code for TLS stack failure.  Suggestion:
 * NGTCP2_ERR_CRYPTO.
 */
typedef int (*ngtcp2_recv_client_initial)(ngtcp2_conn *conn,
                                          const ngtcp2_cid *dcid,
                                          void *user_data);
|#
(define _ngtcp2_recv_client_initial _fpointer)

(define _ngtcp2_crypto_level
  (_enum '(initial handshake application early)))

#|
/**
 * @functypedef
 *
 * :type`ngtcp2_recv_crypto_data` is invoked when crypto data is
 * received.  The received data is pointed to by |data|, and its
 * length is |datalen|.  The |offset| specifies the offset where
 * |data| is positioned.  |user_data| is the arbitrary pointer passed
 * to `ngtcp2_conn_client_new` or `ngtcp2_conn_server_new`.  The
 * ngtcp2 library ensures that the crypto data is passed to the
 * application in the increasing order of |offset|.  |datalen| is
 * always strictly greater than 0.  |crypto_level| indicates the
 * encryption level where this data is received.  Crypto data can
 * never be received in
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`.
 *
 * The application should provide the given data to TLS stack.
 *
 * The callback function must return 0 if it succeeds.  If TLS stack
 * reported error, return :macro:`NGTCP2_ERR_CRYPTO`.  If application
 * encounters fatal error, return :macro:`NGTCP2_ERR_CALLBACK_FAILURE`
 * which makes the library call return immediately.  If the other
 * value is returned, it is treated as
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*ngtcp2_recv_crypto_data)(ngtcp2_conn *conn,
                                       ngtcp2_crypto_level crypto_level,
                                       uint64_t offset, const uint8_t *data,
                                       size_t datalen, void *user_data);
|#
(define _ngtcp2_recv_crypto_data _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_handshake_completed` is invoked when QUIC
 * cryptographic handshake has completed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_handshake_completed)(ngtcp2_conn *conn, void *user_data);
|#
(define _ngtcp2_handshake_completed _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_handshake_confirmed` is invoked when QUIC
 * cryptographic handshake is confirmed.  The handshake confirmation
 * means that both endpoints agree that handshake has finished.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_handshake_confirmed)(ngtcp2_conn *conn, void *user_data);
|#
(define _ngtcp2_handshake_confirmed _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_version_negotiation` is invoked when Version
 * Negotiation packet is received.  |hd| is the pointer to the QUIC
 * packet header object.  The vector |sv| of |nsv| elements contains
 * the QUIC version the server supports.  Since Version Negotiation is
 * only sent by server, this callback function is used by client only.
 *
 * The callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef int (*ngtcp2_recv_version_negotiation)(ngtcp2_conn *conn,
                                               const ngtcp2_pkt_hd *hd,
                                               const uint32_t *sv, size_t nsv,
                                               void *user_data);
|#
(define _ngtcp2_recv_version_negotiation _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_retry` is invoked when Retry packet is received.
 * This callback is client only.
 *
 * Application must regenerate packet protection key, IV, and header
 * protection key for Initial packets using the destination connection
 * ID obtained by `ngtcp2_conn_get_dcid()` and install them by calling
 * `ngtcp2_conn_install_initial_key()`.
 *
 * 0-RTT data accepted by the ngtcp2 library will be retransmitted by
 * the library automatically.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_recv_retry)(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                                 void *user_data);
|#
(define _ngtcp2_recv_retry _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_encrypt` is invoked when the ngtcp2 library asks the
 * application to encrypt packet payload.  The packet payload to
 * encrypt is passed as |plaintext| of length |plaintextlen|.  The
 * AEAD cipher is |aead|.  |aead_ctx| is the AEAD cipher context
 * object which is initialized with encryption key.  The nonce is
 * passed as |nonce| of length |noncelen|.  The ad, Additional Data to
 * AEAD, is passed as |ad| of length |adlen|.
 *
 * The implementation of this callback must encrypt |plaintext| using
 * the negotiated cipher suite and write the ciphertext into the
 * buffer pointed by |dest|.  |dest| has enough capacity to store the
 * ciphertext.
 *
 * |dest| and |plaintext| may point to the same buffer.
 *
 * The callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 * return immediately.
 */
typedef int (*ngtcp2_encrypt)(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                              const ngtcp2_crypto_aead_ctx *aead_ctx,
                              const uint8_t *plaintext, size_t plaintextlen,
                              const uint8_t *nonce, size_t noncelen,
                              const uint8_t *ad, size_t adlen);
|#
(define _ngtcp2_encrypt _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_decrypt` is invoked when the ngtcp2 library asks the
 * application to decrypt packet payload.  The packet payload to
 * decrypt is passed as |ciphertext| of length |ciphertextlen|.  The
 * AEAD cipher is |aead|.  |aead_ctx| is the AEAD cipher context
 * object which is initialized with decryption key.  The nonce is
 * passed as |nonce| of length |noncelen|.  The ad, Additional Data to
 * AEAD, is passed as |ad| of length |adlen|.
 *
 * The implementation of this callback must decrypt |ciphertext| using
 * the negotiated cipher suite and write the ciphertext into the
 * buffer pointed by |dest|.  |dest| has enough capacity to store the
 * cleartext.
 *
 * |dest| and |ciphertext| may point to the same buffer.
 *
 * The callback function must return 0 if it succeeds.  If TLS stack
 * fails to decrypt data, return :macro:`NGTCP2_ERR_TLS_DECRYPT`.  For
 * any other errors, return :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which
 * makes the library call return immediately.
 */
typedef int (*ngtcp2_decrypt)(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                              const ngtcp2_crypto_aead_ctx *aead_ctx,
                              const uint8_t *ciphertext, size_t ciphertextlen,
                              const uint8_t *nonce, size_t noncelen,
                              const uint8_t *ad, size_t adlen);
|#
(define _ngtcp2_decrypt _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_hp_mask` is invoked when the ngtcp2 library asks the
 * application to produce mask to encrypt or decrypt packet header.
 * The encryption cipher is |hp|.  |hp_ctx| is the cipher context
 * object which is initialized with header protection key.  The sample
 * is passed as |sample| which is :macro:`NGTCP2_HP_SAMPLELEN` bytes
 * long.
 *
 * The implementation of this callback must produce a mask using the
 * header protection cipher suite specified by QUIC specification and
 * write the result into the buffer pointed by |dest|.  The length of
 * mask must be at least :macro:`NGTCP2_HP_MASKLEN`.  The library only
 * uses the first :macro:`NGTCP2_HP_MASKLEN` bytes of the produced
 * mask.  The buffer pointed by |dest| is guaranteed to have at least
 * :macro:`NGTCP2_HP_SAMPLELEN` bytes available for convenience.
 *
 * The callback function must return 0 if it succeeds, or
 *  :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library call
 *  return immediately.
 */
typedef int (*ngtcp2_hp_mask)(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                              const ngtcp2_crypto_cipher_ctx *hp_ctx,
                              const uint8_t *sample);
|#
(define _ngtcp2_hp_mask _fpointer)

(define NGTCP2_STREAM_DATA_FLAG_NONE #x00)
(define NGTCP2_STREAM_DATA_FLAG_FIN #x01)
(define NGTCP2_STREAM_DATA_FLAG_EARLY #x02)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_stream_data` is invoked when stream data is
 * received.  The stream is specified by |stream_id|.  |flags| is the
 * bitwise-OR of zero or more of NGTCP2_STREAM_DATA_FLAG_*.  See
 * :macro:`NGTCP2_STREAM_DATA_FLAG_NONE`.  If |flags| &
 * :macro:`NGTCP2_STREAM_DATA_FLAG_FIN` is nonzero, this portion of
 * the data is the last data in this stream.  |offset| is the offset
 * where this data begins.  The library ensures that data is passed to
 * the application in the non-decreasing order of |offset|.  The data
 * is passed as |data| of length |datalen|.  |datalen| may be 0 if and
 * only if |fin| is nonzero.
 *
 * If :macro:`NGTCP2_STREAM_DATA_FLAG_EARLY` is set in |flags|, it
 * indicates that a part of or whole data was received in 0RTT packet
 * and a handshake has not completed yet.
 *
 * The callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library return
 * immediately.
 */
typedef int (*ngtcp2_recv_stream_data)(ngtcp2_conn *conn, uint32_t flags,
                                       int64_t stream_id, uint64_t offset,
                                       const uint8_t *data, size_t datalen,
                                       void *user_data, void *stream_user_data);
|#
(define _ngtcp2_recv_stream_data _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_open` is a callback function which is called
 * when remote stream is opened by peer.  This function is not called
 * if stream is opened by implicitly (we might reconsider this
 * behaviour).
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_stream_open)(ngtcp2_conn *conn, int64_t stream_id,
                                  void *user_data);
|#
(define _ngtcp2_stream_open _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_close` is invoked when a stream is closed.
 * This callback is not called when QUIC connection is closed before
 * existing streams are closed.  |app_error_code| indicates the error
 * code of this closure.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_stream_close)(ngtcp2_conn *conn, int64_t stream_id,
                                   uint64_t app_error_code, void *user_data,
                                   void *stream_user_data);
|#
(define _ngtcp2_stream_close _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_reset` is invoked when a stream identified by
 * |stream_id| is reset by a remote endpoint.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_stream_reset)(ngtcp2_conn *conn, int64_t stream_id,
                                   uint64_t final_size, uint64_t app_error_code,
                                   void *user_data, void *stream_user_data);
|#
(define _ngtcp2_stream_reset _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_acked_stream_data_offset` is a callback function
 * which is called when stream data is acked, and application can free
 * the data.  The acked range of data is [offset, offset + datalen).
 * For a given stream_id, this callback is called sequentially in
 * increasing order of |offset|.  |datalen| is normally strictly
 * greater than 0.  One exception is that when a packet which includes
 * STREAM frame which has fin flag set, and 0 length data, this
 * callback is invoked with 0 passed as |datalen|.
 *
 * If a stream is closed prematurely and stream data is still
 * in-flight, this callback function is not called for those data.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_acked_stream_data_offset)(
    ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen,
    void *user_data, void *stream_user_data);
|#
(define _ngtcp2_acked_stream_data_offset _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_acked_crypto_offset` is a callback function which is
 * called when crypto stream data is acknowledged, and application can
 * free the data.  |crypto_level| indicates the encryption level where
 * this data was sent.  Crypto data never be sent in
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`.  This works
 * like :type:`ngtcp2_acked_stream_data_offset` but crypto stream has
 * no stream_id and stream_user_data, and |datalen| never become 0.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_acked_crypto_offset)(ngtcp2_conn *conn,
                                          ngtcp2_crypto_level crypto_level,
                                          uint64_t offset, uint64_t datalen,
                                          void *user_data);
|#
(define _ngtcp2_acked_crypto_offset _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_stateless_reset` is a callback function which is
 * called when Stateless Reset packet is received.  The stateless
 * reset details are given in |sr|.
 *
 * The implementation of this callback should return 0 if it succeeds.
 * Returning :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library
 * call return immediately.
 */
typedef int (*ngtcp2_recv_stateless_reset)(ngtcp2_conn *conn,
                                           const ngtcp2_pkt_stateless_reset *sr,
                                           void *user_data);
|#
(define _ngtcp2_recv_stateless_reset _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_extend_max_streams` is a callback function which is
 * called every time max stream ID is strictly extended.
 * |max_streams| is the cumulative number of streams which an endpoint
 * can open.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_extend_max_streams)(ngtcp2_conn *conn,
                                         uint64_t max_streams, void *user_data);
|#
(define _ngtcp2_extend_max_streams _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_extend_max_stream_data` is a callback function which
 * is invoked when max stream data is extended.  |stream_id|
 * identifies the stream.  |max_data| is a cumulative number of bytes
 * the endpoint can send on this stream.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_extend_max_stream_data)(ngtcp2_conn *conn,
                                             int64_t stream_id,
                                             uint64_t max_data, void *user_data,
                                             void *stream_user_data);
|#
(define _ngtcp2_extend_max_stream_data _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_rand` is a callback function to get randomized byte
 * string from application.  Application must fill random |destlen|
 * bytes to the buffer pointed by |dest|.  The generated bytes are
 * used only in non-cryptographic context.
 */
typedef void (*ngtcp2_rand)(uint8_t *dest, size_t destlen,
                            const ngtcp2_rand_ctx *rand_ctx);
|#
(define _ngtcp2_rand _fpointer)
(define _ngtcp2_rand-function
  (_fun [dest : _pointer]
        [destlen : _size]
        [rand_ctx : #;const _ngtcp2_rand_ctx*]
        -> _void))

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_get_new_connection_id` is a callback function to ask
 * an application for new connection ID.  Application must generate
 * new unused connection ID with the exact |cidlen| bytes and store it
 * in |cid|.  It also has to generate stateless reset token into
 * |token|.  The length of stateless reset token is
 * :macro:`NGTCP2_STATELESS_RESET_TOKENLEN` and it is guaranteed that
 * the buffer pointed by |cid| has the sufficient space to store the
 * token.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_get_new_connection_id)(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                            uint8_t *token, size_t cidlen,
                                            void *user_data);
|#
(define _ngtcp2_get_new_connection_id _fpointer)
(define _ngtcp2_get_new_connection_id-function
  (_fun [conn : _ngtcp2_conn*]
        [cid : _ngtcp2_cid*]
        [token : _pointer]
        [cidlen : _size]
        [user_data : _pointer]
        -> _int))

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_remove_connection_id` is a callback function which
 * notifies the application that connection ID |cid| is no longer used
 * by remote endpoint.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_remove_connection_id)(ngtcp2_conn *conn,
                                           const ngtcp2_cid *cid,
                                           void *user_data);
|#
(define _ngtcp2_remove_connection_id _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_update_key` is a callback function which tells the
 * application that it must generate new packet protection keying
 * materials and AEAD cipher context objects with new keys.  The
 * current set of secrets are given as |current_rx_secret| and
 * |current_tx_secret| of length |secretlen|.  They are decryption and
 * encryption secrets respectively.
 *
 * The application has to generate new secrets and keys for both
 * encryption and decryption, and write decryption secret and IV to
 * the buffer pointed by |rx_secret| and |rx_iv| respectively.  It
 * also has to create new AEAD cipher context object with new
 * decryption key and initialize |rx_aead_ctx| with it.  Similarly,
 * write encryption secret and IV to the buffer pointed by |tx_secret|
 * and |tx_iv|.  Create new AEAD cipher context object with new
 * encryption key and initialize |tx_aead_ctx| with it.  All given
 * buffers have the enough capacity to store secret, key and IV.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_update_key)(
    ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
    ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
    ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
    const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
    size_t secretlen, void *user_data);
|#
(define _ngtcp2_update_key _fpointer)

(define NGTCP2_PATH_VALIDATION_FLAG_NONE 0)
(define NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR #x01)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_path_validation` is a callback function which tells
 * the application the outcome of path validation.  |flags| is zero or
 * more of NGTCP2_PATH_VALIDATION_FLAG_*.  See
 * :macro:`NGTCP2_PATH_VALIDATION_FLAG_NONE`.  |path| is the path that
 * was validated.  If |res| is
 * :enum:`ngtcp2_path_validation_result.NGTCP2_PATH_VALIDATION_RESULT_SUCCESS`,
 * the path validation succeeded.  If |res| is
 * :enum:`ngtcp2_path_validation_result.NGTCP2_PATH_VALIDATION_RESULT_FAILURE`,
 * the path validation failed.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_path_validation)(ngtcp2_conn *conn, uint32_t flags,
                                      const ngtcp2_path *path,
                                      ngtcp2_path_validation_result res,
                                      void *user_data);
|#
(define _ngtcp2_path_validation _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_select_preferred_addr` is a callback function which
 * asks a client application to choose server address from preferred
 * addresses |paddr| received from server.  An application should
 * write a network path for a selected preferred address in |dest|.
 * More specifically, the selected preferred address must be set to
 * :member:`dest->remote <ngtcp2_path.remote>`, a client source
 * address must be set to :member:`dest->local <ngtcp2_path.local>`.
 * If a client source address does not change for the new server
 * address, leave :member:`dest->local <ngtcp2_path.local>`
 * unmodified, or copy the value of :member:`local
 * <ngtcp2_path.local>` field of the current network path obtained
 * from `ngtcp2_conn_get_path()`.  Both :member:`dest->local.addr
 * <ngtcp2_addr.addr>` and :member:`dest->remote.addr
 * <ngtcp2_addr.addr>` point to buffers which are at least
 * ``sizeof(struct sockaddr_storage)`` bytes long, respectively.  If
 * an application denies the preferred addresses, just leave |dest|
 * unmodified (or set :member:`dest->remote.addrlen
 * <ngtcp2_addr.addrlen>` to 0) and return 0.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_select_preferred_addr)(ngtcp2_conn *conn,
                                            ngtcp2_path *dest,
                                            const ngtcp2_preferred_addr *paddr,
                                            void *user_data);
|#
(define _ngtcp2_select_preferred_addr _fpointer)

(define _ngtcp2_connection_id_status_type
  (_enum '(activate deactivate)))

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_connection_id_status` is a callback function which is
 * called when the status of Connection ID changes.
 *
 * |token| is the associated stateless reset token and it is ``NULL``
 * if no token is present.
 *
 * |type| is the one of the value defined in
 * :type:`ngtcp2_connection_id_status_type`.  The new value might be
 * added in the future release.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_connection_id_status)(ngtcp2_conn *conn, int type,
                                           uint64_t seq, const ngtcp2_cid *cid,
                                           const uint8_t *token,
                                           void *user_data);
|#
(define _ngtcp2_connection_id_status _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_new_token` is a callback function which is
 * called when new token is received from server.
 *
 * |token| is the received token.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_recv_new_token)(ngtcp2_conn *conn, const ngtcp2_vec *token,
                                     void *user_data);
|#
(define _ngtcp2_recv_new_token _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_delete_crypto_aead_ctx` is a callback function which
 * must delete the native object pointed by
 * :member:`aead_ctx->native_handle
 * <ngtcp2_crypto_aead_ctx.native_handle>`.
 */
typedef void (*ngtcp2_delete_crypto_aead_ctx)(ngtcp2_conn *conn,
                                              ngtcp2_crypto_aead_ctx *aead_ctx,
                                              void *user_data);
|#
(define _ngtcp2_delete_crypto_aead_ctx _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_delete_crypto_cipher_ctx` is a callback function
 * which must delete the native object pointed by
 * :member:`cipher_ctx->native_handle
 * <ngtcp2_crypto_cipher_ctx.native_handle>`.
 */
typedef void (*ngtcp2_delete_crypto_cipher_ctx)(
    ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data);
|#
(define _ngtcp2_delete_crypto_cipher_ctx _fpointer)

;; Datagram flags

(define NGTCP2_DATAGRAM_FLAG_NONE #x00)
(define NGTCP2_DATAGRAM_FLAG_EARLY #x01)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_recv_datagram` is invoked when DATAGRAM frame is
 * received.  |flags| is bitwise-OR of zero or more of
 * NGTCP2_DATAGRAM_FLAG_*.  See :macro:`NGTCP2_DATAGRAM_FLAG_NONE`.
 *
 * If :macro:`NGTCP2_DATAGRAM_FLAG_EARLY` is set in |flags|, it
 * indicates that DATAGRAM frame was received in 0RTT packet and a
 * handshake has not completed yet.
 *
 * The callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library return
 * immediately.
 */
typedef int (*ngtcp2_recv_datagram)(ngtcp2_conn *conn, uint32_t flags,
                                    const uint8_t *data, size_t datalen,
                                    void *user_data);
|#
(define _ngtcp2_recv_datagram _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_ack_datagram` is invoked when a packet which contains
 * DATAGRAM frame which is identified by |dgram_id| is acknowledged.
 * |dgram_id| is the valued passed to `ngtcp2_conn_writev_datagram`.
 *
 * The callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library return
 * immediately.
 */
typedef int (*ngtcp2_ack_datagram)(ngtcp2_conn *conn, uint64_t dgram_id,
                                   void *user_data);
|#
(define _ngtcp2_ack_datagram _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_lost_datagram` is invoked when a packet which
 * contains DATAGRAM frame which is identified by |dgram_id| is
 * declared lost.  |dgram_id| is the valued passed to
 * `ngtcp2_conn_writev_datagram`.
 *
 * The callback function must return 0 if it succeeds, or
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` which makes the library return
 * immediately.
 */
typedef int (*ngtcp2_lost_datagram)(ngtcp2_conn *conn, uint64_t dgram_id,
                                    void *user_data);
|#
(define _ngtcp2_lost_datagram _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_get_path_challenge_data` is a callback function to
 * ask an application for new data that is sent in PATH_CHALLENGE
 * frame.  Application must generate new unpredictable exactly
 * :macro:`NGTCP2_PATH_CHALLENGE_DATALEN` bytes of random data and
 * store them into the buffer pointed by |data|.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_get_path_challenge_data)(ngtcp2_conn *conn, uint8_t *data,
                                              void *user_data);
|#
(define _ngtcp2_get_path_challenge_data _fpointer)

#|
/**
 * @functypedef
 *
 * :type:`ngtcp2_stream_stop_sending` is invoked when a stream is no
 * longer read by a local endpoint before it receives all stream data.
 * This function is called at most once per stream.  |app_error_code|
 * is the error code passed to `ngtcp2_conn_shutdown_stream_read` or
 * `ngtcp2_conn_shutdown_stream`.
 *
 * The callback function must return 0 if it succeeds.  Returning
 * :macro:`NGTCP2_ERR_CALLBACK_FAILURE` makes the library call return
 * immediately.
 */
typedef int (*ngtcp2_stream_stop_sending)(ngtcp2_conn *conn, int64_t stream_id,
                                          uint64_t app_error_code,
                                          void *user_data,
                                          void *stream_user_data);
|#
(define _ngtcp2_stream_stop_sending _fpointer)

(define-cstruct _ngtcp2_callbacks
  ([client_initial _ngtcp2_client_initial]
   [recv_client_initial _ngtcp2_recv_client_initial]
   [recv_crypto_data _ngtcp2_recv_crypto_data]
   [handshake_completed _ngtcp2_handshake_completed]
   [recv_version_negotiation _ngtcp2_recv_version_negotiation]
   [encrypt _ngtcp2_encrypt]
   [decrypt _ngtcp2_decrypt]
   [hp_mask _ngtcp2_hp_mask]
   [recv_stream_data _ngtcp2_recv_stream_data]
   [acked_crypto_offset _ngtcp2_acked_crypto_offset]
   [acked_stream_data_offset _ngtcp2_acked_stream_data_offset]
   [stream_open _ngtcp2_stream_open]
   [stream_close _ngtcp2_stream_close]
   [recv_stateless_reset _ngtcp2_recv_stateless_reset]
   [recv_retry _ngtcp2_recv_retry]
   [extend_max_local_streams_bidi _ngtcp2_extend_max_streams]
   [extend_max_local_streams_uni _ngtcp2_extend_max_streams]
   [rand _ngtcp2_rand]
   [get_new_connection_id _ngtcp2_get_new_connection_id]
   [remove_connection_id _ngtcp2_remove_connection_id]
   [update_key _ngtcp2_update_key]
   [path_validation _ngtcp2_path_validation]
   [select_preferred_addr _ngtcp2_select_preferred_addr]
   [stream_reset _ngtcp2_stream_reset]
   [extend_max_remote_streams_bidi _ngtcp2_extend_max_streams]
   [extend_max_remote_streams_uni _ngtcp2_extend_max_streams]
   [extend_max_stream_data _ngtcp2_extend_max_stream_data]
   [dcid_status _ngtcp2_connection_id_status]
   [handshake_confirmed _ngtcp2_handshake_confirmed]
   [recv_new_token _ngtcp2_recv_new_token]
   [delete_crypto_aead_ctx _ngtcp2_delete_crypto_aead_ctx]
   [delete_crypto_cipher_ctx _ngtcp2_delete_crypto_cipher_ctx]
   [recv_datagram _ngtcp2_recv_datagram]
   [ack_datagram _ngtcp2_ack_datagram]
   [lost_datagram _ngtcp2_lost_datagram]
   [get_path_challenge_data _ngtcp2_get_path_challenge_data]
   [stream_stop_sending _ngtcp2_stream_stop_sending]))
(define _ngtcp2_callbacks* _ngtcp2_callbacks-pointer/null)

(define-ng ngtcp2_pkt_write_connection_close
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [version : _uint32]
        [dcid : #;const _ngtcp2_cid*]
        [scid : #;const _ngtcp2_cid*]
        [error_code : _uint64]
        [encrypt : _ngtcp2_encrypt]
        [aead : #;const _ngtcp2_crypto_aead*]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [iv : #;const _pointer]
        [hp_mask : _ngtcp2_hp_mask]
        [hp : #;const _ngtcp2_crypto_cipher*]
        [hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_pkt_write_retry
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [version : _uint32]
        [dcid : #;const _ngtcp2_cid*]
        [scid : #;const _ngtcp2_cid*]
        [odcid : #;const _ngtcp2_cid*]
        [token : #;const _bytes]
        [tokenlen : _size = (bytes-length token)]
        [encrypt : _ngtcp2_encrypt]
        [aead : #;const _ngtcp2_crypto_aead*]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_accept
  (_fun [dest : _ngtcp2_pkt_hd*]
        [pkt : #;const _bytes]
        [pktlen : _size = (bytes-length pkt)]
        -> _int))

(define-ng ngtcp2_conn_client_new
  (_fun [pconn : (_ptr o _ngtcp2_conn*)]
        [dcid : #;const _ngtcp2_cid*]
        [scid : #;const _ngtcp2_cid*]
        [path : #;const _ngtcp2_path*]
        [version : _uint32]
        [callbacks : #;const _ngtcp2_callbacks*]  ;; copied
        [settings : #;const _ngtcp2_settings*]    ;; copied
        [params : #;const _ngtcp2_transport_params*] ;; copied
        [mem : #;const _ngtcp2_mem* = #f]
        [user_data : _pointer]
        -> (r : _int)
        -> (if (zero? r) pconn #f)))

(define-ng ngtcp2_conn_server_new
  (_fun [pconn : (_ptr o _ngtcp2_conn*)]
        [dcid : #;const _ngtcp2_cid*]
        [scid : #;const _ngtcp2_cid*]
        [path : #;const _ngtcp2_path*]
        [version : _uint32]
        [callbacks : #;const _ngtcp2_callbacks*] ;; copied
        [settings : #;const _ngtcp2_settings*]   ;; copied
        [params : #;const _ngtcp2_transport_params*] ;; copied
        [mem : #;const _ngtcp2_mem* = #f]
        [user_data : _pointer]
        -> (r : _int)
        -> (if (zero? r) pconn #f)))

(define-ng ngtcp2_conn_del
  (_fun [conn : _ngtcp2_conn*]
        -> _void))

(define-ng ngtcp2_conn_read_pkt
  (_fun [conn : _ngtcp2_conn*]
        [path : #;const _ngtcp2_path*]
        [pi : #;const _ngtcp2_pkt_info*]
        [pkt : #;const _bytes]
        [pktlen : _size = (bytes-length pkt)]
        [ts : _ngtcp2_tstamp]
        -> _int))

(define-ng ngtcp2_conn_write_pkt
  (_fun [conn : _ngtcp2_conn*]
        [path : _ngtcp2_path*]
        [pi : _ngtcp2_pkt_info*]
        [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [ts : _ngtcp2_tstamp]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_conn_handshake_completed
  (_fun [conn : _ngtcp2_conn*]
        -> _void))

(define-ng ngtcp2_conn_get_handshake_completed
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_install_initial_key
  (_fun [conn : _ngtcp2_conn*]
        [rx_aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [rx_iv : #;const _pointer]
        [rx_hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        [tx_aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [tx_iv : #;const _pointer]
        [tx_hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        [ivlen : _size]
        -> _int))

(define-ng ngtcp2_conn_install_rx_handshake_key
  (_fun [conn : _ngtcp2_conn*]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [iv : #;const _bytes]
        [ivlen : _size = (bytes-length iv)]
        [hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        -> _int))

(define-ng ngtcp2_conn_install_tx_handshake_key
  (_fun [conn : _ngtcp2_conn*]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [iv : #;const _bytes]
        [ivlen : _size = (bytes-length iv)]
        [hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        -> _int))

(define-ng ngtcp2_conn_install_early_key
  (_fun [conn : _ngtcp2_conn*]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [iv : #;const _bytes]
        [ivlen : _size = (bytes-length iv)]
        [hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        -> _int))

(define-ng ngtcp2_conn_install_rx_key
  (_fun [conn : _ngtcp2_conn*]
        [secret : #;const _pointer]
        [secretlen : _size]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [iv : #;const _bytes]
        [ivlen : _size = (bytes-length iv)]
        [hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        -> _int))

(define-ng ngtcp2_conn_install_tx_key
  (_fun [conn : _ngtcp2_conn*]
        [secret : #;const _bytes]
        [secretlen : _size = (bytes-length secret)]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        [iv : #;const _bytes]
        [ivlen : _size = (bytes-length iv)]
        [hp_ctx : #;const _ngtcp2_crypto_cipher_ctx*]
        -> _int))

(define-ng ngtcp2_conn_initiate_key_update
  (_fun [conn : _ngtcp2_conn*]
        [ts : _ngtcp2_tstamp]
        -> _int))

(define-ng ngtcp2_conn_set_tls_error
  (_fun [conn : _ngtcp2_conn*]
        [liberr : _int]
        -> _void))

(define-ng ngtcp2_conn_get_tls_error
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_set_keep_alive_timeout
  (_fun [conn : _ngtcp2_conn*]
        [timeout : _ngtcp2_duration]
        -> _void))

(define-ng ngtcp2_conn_get_expiry
  (_fun [conn : _ngtcp2_conn*]
        -> _ngtcp2_tstamp))

(define-ng ngtcp2_conn_handle_expiry
  (_fun [conn : _ngtcp2_conn*]
        [ts : _ngtcp2_tstamp]
        -> _int))

(define-ng ngtcp2_conn_get_idle_expiry
  (_fun [conn : _ngtcp2_conn*]
        -> _ngtcp2_tstamp))

(define-ng ngtcp2_conn_get_pto
  (_fun [conn : _ngtcp2_conn*]
        -> _ngtcp2_duration))

(define-ng ngtcp2_conn_set_remote_transport_params
  (_fun [conn : _ngtcp2_conn*]
        [params : #;const _ngtcp2_transport_params*]
        -> _int))

(define-ng ngtcp2_conn_get_remote_transport_params
  (_fun [conn : _ngtcp2_conn*]
        [params : _ngtcp2_transport_params*]
        -> _void))

(define-ng ngtcp2_conn_set_early_remote_transport_params
  (_fun [conn : _ngtcp2_conn*]
        [params : #;const _ngtcp2_transport_params*]
        -> _void))

(define-ng ngtcp2_conn_set_local_transport_params
  (_fun [conn : _ngtcp2_conn*]
        [params : #;const _ngtcp2_transport_params*]
        -> _int))

(define-ng ngtcp2_conn_get_local_transport_params
  (_fun [conn : _ngtcp2_conn*]
        [params : _ngtcp2_transport_params*]
        -> _void))

(define-ng ngtcp2_conn_open_bidi_stream
  (_fun [conn : _ngtcp2_conn*]
        [pstream_id : (_ptr o _int64)]
        [stream_user_data : _pointer]
        -> (r : _int)
        -> (values r pstream_id)))

(define-ng ngtcp2_conn_open_uni_stream
  (_fun [conn : _ngtcp2_conn*]
        [pstream_id : (_ptr o _int64)]
        [stream_user_data : _pointer]
        -> (r : _int)
        -> (values r pstream_id)))

(define-ng ngtcp2_conn_shutdown_stream
  (_fun [conn : _ngtcp2_conn*]
        [stream_id : _int64]
        [app_error_code : _uint64]
        -> _int))

(define-ng ngtcp2_conn_shutdown_stream_write
  (_fun [conn : _ngtcp2_conn*]
        [stream_id : _int64]
        [app_error_code : _uint64]
        -> _int))

(define-ng ngtcp2_conn_shutdown_stream_read
  (_fun [conn : _ngtcp2_conn*]
        [stream_id : _int64]
        [app_error_code : _uint64]
        -> _int))

(define NGTCP2_WRITE_STREAM_FLAG_NONE #x00)
(define NGTCP2_WRITE_STREAM_FLAG_MORE #x01)
(define NGTCP2_WRITE_STREAM_FLAG_FIN #x02)

(define-ng ngtcp2_conn_write_stream
  (_fun [conn : _ngtcp2_conn*]
        [path : _ngtcp2_path*]
        [pi : _ngtcp2_pkt_info*]
        [dest : _pointer] ;; FIXME: must not move!
        [destlen : _size]
        [pdatalen : (_ptr o _ngtcp2_ssize)]
        [flags : _uint32]
        [stream_id : _int64]
        [data : #;const _pointer]
        [datalen : _size]
        [ts : _ngtcp2_tstamp]
        -> (r : _ngtcp2_ssize)
        -> (values r pdatalen)))

(define-ng ngtcp2_conn_writev_stream
  (_fun [conn : _ngtcp2_conn*]
        [path : _ngtcp2_path*]
        [pi : _ngtcp2_pkt_info*]
        [dest : _pointer] ;; FIXME: must not move!
        [destlen : _size]
        [pdatalen : (_ptr o _ngtcp2_ssize)]
        [flags : _uint32]
        [stream_id : _int64]
        [datav : #;const _ngtcp2_vec*]
        [datavcnt : _size]
        [ts : _ngtcp2_tstamp]
        -> (r : _ngtcp2_ssize)
        -> (values r pdatalen)))

(define NGTCP2_WRITE_DATAGRAM_FLAG_NONE #x00)
(define NGTCP2_WRITE_DATAGRAM_FLAG_MORE #x01)

(define-ng ngtcp2_conn_writev_datagram
  (_fun [conn : _ngtcp2_conn*]
        [path : _ngtcp2_path*]
        [pi : _ngtcp2_pkt_info*]
        [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [paccepted : (_ptr o _int)] ;; FIXME
        [flags : _uint32]
        [dgram_id : _uint64]
        [datav : #;const _ngtcp2_vec*]
        [datavcnt : _size]
        [ts : _ngtcp2_tstamp]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_conn_write_connection_close
  (_fun [conn : _ngtcp2_conn*]
        [path : _ngtcp2_path*]
        [pi : _ngtcp2_pkt_info*]
        [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [error_code : _uint64]
        [ts : _ngtcp2_tstamp]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_conn_write_application_close
  (_fun [conn : _ngtcp2_conn*]
        [path : _ngtcp2_path*]
        [pi : _ngtcp2_pkt_info*]
        [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [app_error_code : _uint64]
        [ts : _ngtcp2_tstamp]
        -> _ngtcp2_ssize))

(define-ng ngtcp2_conn_is_in_closing_period
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_is_in_draining_period
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_extend_max_stream_offset
  (_fun [conn : _ngtcp2_conn*]
        [stream_id : _int64]
        [datalen : _uint64]
        -> _int))

(define-ng ngtcp2_conn_extend_max_offset
  (_fun [conn : _ngtcp2_conn*]
        [datalen : _uint64]
        -> _void))

(define-ng ngtcp2_conn_extend_max_streams_bidi
  (_fun [conn : _ngtcp2_conn*]
        [n : _size]
        -> _void))

(define-ng ngtcp2_conn_extend_max_streams_uni
  (_fun [conn : _ngtcp2_conn*]
        [n : _size]
        -> _void))

(define-ng ngtcp2_conn_get_dcid
  (_fun [conn : _ngtcp2_conn*]
        -> #;const _ngtcp2_cid*))


(define-ng ngtcp2_conn_get_num_scid
  (_fun [conn : _ngtcp2_conn*]
        -> _size))

(define-ng ngtcp2_conn_get_scid
  (_fun [conn : _ngtcp2_conn*]
        [dest : _ngtcp2_cid*]
        -> _size))

(define-ng ngtcp2_conn_get_num_active_dcid
  (_fun [conn : _ngtcp2_conn*]
        -> _size))

(define-cstruct _ngtcp2_cid_token
  ([seq _uint64]
   [cid _ngtcp2_cid]
   [ps _ngtcp2_path_storage]
   [token (_array _uint8 NGTCP2_STATELESS_RESET_TOKENLEN)]
   [token_present _uint8]))
(define _ngtcp2_cid_token* _ngtcp2_cid_token-pointer/null)

(define-ng ngtcp2_conn_get_active_dcid
  (_fun [conn : _ngtcp2_conn*]
        [dest : _ngtcp2_cid_token*]
        -> _size))

(define-ng ngtcp2_conn_get_negotiated_version
  (_fun [conn : _ngtcp2_conn*]
        -> _uint32))

(define-ng ngtcp2_conn_early_data_rejected
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_get_conn_stat
  (_fun [conn : _ngtcp2_conn*]
        [cstat : _ngtcp2_conn_stat*]
        -> _void))

(define-ng ngtcp2_conn_on_loss_detection_timer
  (_fun [conn : _ngtcp2_conn*]
        [ts : _ngtcp2_tstamp]
        -> _int))

(define-ng ngtcp2_conn_submit_crypto_data
  (_fun [conn : _ngtcp2_conn*]
        [crypto_level : _ngtcp2_crypto_level]
        [data : #;const _bytes]
        [datalen : #;const _size = (bytes-length data)]
        -> _int))

(define-ng ngtcp2_conn_submit_new_token
  (_fun [conn : _ngtcp2_conn*]
        [token : #;const _bytes]
        [tokenlen : _size = (bytes-length token)]
        -> _int))

(define-ng ngtcp2_conn_set_local_addr
  (_fun [conn : _ngtcp2_conn*]
        [addr : #;const _ngtcp2_addr*]
        -> _void))

(define-ng ngtcp2_conn_get_path
  (_fun [conn : _ngtcp2_conn*]
        -> #;const _ngtcp2_path*))

(define-ng ngtcp2_conn_initiate_immediate_migration
  (_fun [conn : _ngtcp2_conn*]
        [local_addr : #;const _ngtcp2_addr*]
        [path_user_data : _pointer]
        [ts : _ngtcp2_tstamp]
        -> _int))

(define-ng ngtcp2_conn_initiate_migration
  (_fun [conn : _ngtcp2_conn*]
        [local_addr : #;const _ngtcp2_addr*]
        [path_user_data : _pointer]
        [ts : _ngtcp2_tstamp]
        -> _int))

(define-ng ngtcp2_conn_get_max_local_streams_uni
  (_fun [conn : _ngtcp2_conn*]
        -> _uint64))

(define-ng ngtcp2_conn_get_max_data_left
  (_fun [conn : _ngtcp2_conn*]
        -> _uint64))

(define-ng ngtcp2_conn_get_streams_bidi_left
  (_fun [conn : _ngtcp2_conn*]
        -> _uint64))

(define-ng ngtcp2_conn_get_streams_uni_left
  (_fun [conn : _ngtcp2_conn*]
        -> _uint64))

(define-ng ngtcp2_conn_set_initial_crypto_ctx
  (_fun [conn : _ngtcp2_conn*]
        [ctx : #;const _ngtcp2_crypto_ctx*]
        -> _void))

(define-ng ngtcp2_conn_get_initial_crypto_ctx
  (_fun [conn : _ngtcp2_conn*]
        -> #;const _ngtcp2_crypto_ctx*))

(define-ng ngtcp2_conn_set_crypto_ctx
  (_fun [conn : _ngtcp2_conn*]
        [ctx : #;const _ngtcp2_crypto_ctx*]
        -> _void))

(define-ng ngtcp2_conn_get_tls_native_handle
  (_fun [conn : _ngtcp2_conn*]
        -> _pointer))

(define-ng ngtcp2_conn_set_tls_native_handle
  (_fun [conn : _ngtcp2_conn*]
        [tls_native_handle : _pointer]
        -> _void))

(define-ng ngtcp2_conn_set_retry_aead
  (_fun [conn : _ngtcp2_conn*]
        [aead : #;const _ngtcp2_crypto_aead*]
        [aead_ctx : #;const _ngtcp2_crypto_aead_ctx*]
        -> _void))

(define-ng ngtcp2_conn_get_crypto_ctx
  (_fun [conn : _ngtcp2_conn*]
        -> #;const _ngtcp2_crypto_ctx*))

(define-ng ngtcp2_conn_set_early_crypto_ctx
  (_fun [conn : _ngtcp2_conn*]
        [ctx : #;const _ngtcp2_crypto_ctx*]
        -> _void))

(define-ng ngtcp2_conn_get_early_crypto_ctx
  (_fun [conn : _ngtcp2_conn*]
        -> #;const _ngtcp2_crypto_ctx*))

(define _ngtcp2_connection_close_error_code_type
  (_enum '(transport application)))

(define-cstruct _ngtcp2_connection_close_error_code
  ([error_code _uint64]
   [type _ngtcp2_connection_close_error_code_type]))

(define-ng ngtcp2_conn_get_connection_close_error_code
  (_fun [conn : _ngtcp2_conn*]
        [ccec : _ngtcp2_connection_close_error_code-pointer
              = (make-ngtcp2_connection_close_error_code 0 'transport)]
        -> _void
        -> ccec))

(define-ng ngtcp2_conn_is_local_stream
  (_fun [conn : _ngtcp2_conn*]
        [stream_id : _int64]
        -> _int))

(define-ng ngtcp2_conn_is_server
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_after_retry
  (_fun [conn : _ngtcp2_conn*]
        -> _int))

(define-ng ngtcp2_conn_set_stream_user_data
  (_fun [conn : _ngtcp2_conn*]
        [stream_id : _int64]
        [stream_user_data : _pointer]
        -> _int))

(define-ng ngtcp2_conn_update_pkt_tx_time
  (_fun [conn : _ngtcp2_conn*]
        [ts : _ngtcp2_tstamp]
        -> _void))

(define-ng ngtcp2_conn_get_send_quantum
  (_fun [conn : _ngtcp2_conn*] -> _size))

(define-ng ngtcp2_strerror
  (_fun [liberr : _int] -> _string/utf-8)) ;; const char*

(define-ng ngtcp2_err_is_fatal
  (_fun [liberr : _int] -> _int))

(define-ng ngtcp2_err_infer_quic_transport_error_code
  (_fun [liberr : _int] -> _uint64))

(define-ng ngtcp2_addr_init
  (_fun [dest : _ngtcp2_addr*]
        [addr : #;const _sockaddr*]
        [addrlen : _size]
        -> _ngtcp2_addr*))

(define-ng ngtcp2_addr_copy_byte
  (_fun [dest : _ngtcp2_addr*]
        [addr : #;const _sockaddr*]
        [addrlen : _size]
        -> _void))

(define-ng ngtcp2_path_storage_init
  (_fun [ps : _ngtcp2_path_storage*]
        [local_addr : #;const _sockaddr*]
        [local_addrlen : _size]
        [remote_addr : #;const _sockaddr*]
        [remote_addrlen : _size]
        [user_data : _pointer]
        -> _void))

(define-ng ngtcp2_path_storage_zero
  (_fun [ps : _ngtcp2_path_storage*]
        -> _void))

(define-ng ngtcp2_settings_default
  (_fun [settings : _ngtcp2_settings*]
        -> _void))

(define-ng ngtcp2_transport_params_default
  (_fun [params : _ngtcp2_transport_params*]
        -> _void))

(define-ng ngtcp2_mem_default
  (_fun -> #;const _ngtcp2_mem*))

(define NGTCP2_VERSION_AGE 1)

(define-cstruct _ngtcp2_info
  ([age _int]
   [version_num _int]
   [version_str _pointer]))
(define _ngtcp2_info* _ngtcp2_info-pointer/null)

(define-ng ngtcp2_version
  (_fun [least_version : _int]
        -> #;const _ngtcp2_info*))

(define-ng ngtcp2_is_bidi_stream
  (_fun [stream_id : _int64] -> _int))

(define _ngtcp2_log_event
  (_enum '(none con pkt frm rcv cry ptv)))

(define-ng ngtcp2_log_info _fpointer)

(define-ng ngtcp2_path_copy
  (_fun [dest : _ngtcp2_path*]
        [src : #;const _ngtcp2_path*]
        -> _void))

(define-ng ngtcp2_path_eq
  (_fun [a : #;const _ngtcp2_path*]
        [b : #;const _ngtcp2_path*]
        -> _int))


;; ============================================================

(define NGTCP2_CRYPTO_INITIAL_SECRETLEN 32)
(define NGTCP2_CRYPTO_INITIAL_KEYLEN 16)
(define NGTCP2_CRYPTO_INITIAL_IVLEN 12)

(define-ngc ngtcp2_crypto_ctx_initial
  (_fun [ctx : _ngtcp2_crypto_ctx*]
        -> _ngtcp2_crypto_ctx*))

(define-ngc ngtcp2_crypto_ctx_tls
  (_fun [ctx : _ngtcp2_crypto_ctx*]
        [tls_native_handle : _pointer] ;; SSL*
        -> _ngtcp2_crypto_ctx*))

(define-ngc ngtcp2_crypto_ctx_tls_early
  (_fun [ctx : _ngtcp2_crypto_ctx*]
        [tls_native_handle : _pointer] ;; SSL*
        -> _ngtcp2_crypto_ctx*))

(define-ngc ngtcp2_crypto_aead_init
  (_fun [aead : _ngtcp2_crypto_aead*]
        [aead_native_handle : _pointer] ;; EVP_CIPHER*
        -> _ngtcp2_crypto_aead*))

(define-ngc ngtcp2_crypto_aead_retry
  (_fun [aead : _ngtcp2_crypto_aead*]
        -> _ngtcp2_crypto_aead*))

(define-ngc ngtcp2_crypto_md_init
  (_fun [md : _ngtcp2_crypto_md*]
        [md_native_handle : _pointer] ;; ???
        -> _ngtcp2_crypto_md*))

(define-ngc ngtcp2_crypto_md_hashlen
  (_fun [md : #;const _ngtcp2_crypto_md*]
        -> _size))

(define-ngc ngtcp2_crypto_aead_keylen
  (_fun [aead : #;const _ngtcp2_crypto_aead*]
        -> _size))

(define-ngc ngtcp2_crypto_aead_noncelen
  (_fun [aead : #;const _ngtcp2_crypto_aead*]
        -> _size))

(define-ngc ngtcp2_crypto_hkdf_extract
  (_fun [dest : _pointer]
        [md : #;const _ngtcp2_crypto_md*]
        [secret : #;const _bytes]
        [secretlen : _size = (bytes-length secret)]
        [salt : #;const _bytes]
        [saltlen : _size = (bytes-length salt)]
        -> _int))

(define-ngc ngtcp2_crypto_hkdf_expand
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [md : #;const _ngtcp2_crypto_md*]
        [secret : #;const _bytes]
        [secretlen : _size = (bytes-length secret)]
        [info : #;const _bytes]
        [infolen : _size = (bytes-length info)]
        -> _int))

(define-ngc ngtcp2_crypto_hkdf_expand_label
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [md : #;const _ngtcp2_crypto_md*]
        [secret : #;const _bytes]
        [secretlen : _size = (bytes-length secret)]
        [label : #;const _bytes]
        [labellen : _size = (bytes-length label)]
        -> _int))

(define _ngtcp2_crypto_side
  (_enum '(client server)))

(define-ngc ngtcp2_crypto_packet_protection_ivlen
  (_fun [aead : #;const _ngtcp2_crypto_aead*]
        -> _size))

(define-ngc ngtcp2_crypto_derive_packet_protection_key
  (_fun [key : _pointer]
        [iv : _pointer]
        [hp : _pointer]
        [aead : #;const _ngtcp2_crypto_aead*]
        [md : #;const _ngtcp2_crypto_md*]
        [secret : #;const _bytes]
        [secretlen : _size = (bytes-length secret)]
        -> _int))

#|
/**
 * @function
 *
 * `ngtcp2_crypto_encrypt` encrypts |plaintext| of length
 * |plaintextlen| and writes the ciphertext into the buffer pointed by
 * |dest|.  The length of ciphertext is plaintextlen +
 * :member:`aead->max_overhead <ngtcp2_crypto_aead.max_overhead>`
 * bytes long.  |dest| must have enough capacity to store the
 * ciphertext.  It is allowed to specify the same value to |dest| and
 * |plaintext|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
int ngtcp2_crypto_encrypt(uint8_t *dest,
                                        const ngtcp2_crypto_aead *aead,
                                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const uint8_t *plaintext,
                                        size_t plaintextlen,
                                        const uint8_t *nonce, size_t noncelen,
                                        const uint8_t *ad, size_t adlen);
|#

(define-ngc ngtcp2_crypto_encrypt_cb _fpointer)

#|
/**
 * @function
 *
 * `ngtcp2_crypto_decrypt` decrypts |ciphertext| of length
 * |ciphertextlen| and writes the plaintext into the buffer pointed by
 * |dest|.  The length of plaintext is ciphertextlen -
 * :member:`aead->max_overhead <ngtcp2_crypto_aead.max_overhead>`
 * bytes long.  |dest| must have enough capacity to store the
 * plaintext.  It is allowed to specify the same value to |dest| and
 * |ciphertext|.
 *
 * This function returns 0 if it succeeds, or -1.
 */
int ngtcp2_crypto_decrypt(uint8_t *dest,
                                        const ngtcp2_crypto_aead *aead,
                                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const uint8_t *ciphertext,
                                        size_t ciphertextlen,
                                        const uint8_t *nonce, size_t noncelen,
                                        const uint8_t *ad, size_t adlen);
|#

(define-ngc ngtcp2_crypto_decrypt_cb _fpointer)

#|
/**
 * @function
 *
 * `ngtcp2_crypto_hp_mask` generates mask which is used in packet
 * header encryption.  The mask is written to the buffer pointed by
 * |dest|.  The sample is passed as |sample| which is
 * :macro:`NGTCP2_HP_SAMPLELEN` bytes long.  The length of mask must
 * be at least :macro:`NGTCP2_HP_MASKLEN`.  The library only uses the
 * first :macro:`NGTCP2_HP_MASKLEN` bytes of the produced mask.  The
 * buffer pointed by |dest| must have at least
 * :macro:`NGTCP2_HP_SAMPLELEN` bytes available.
 *
 * This function returns 0 if it succeeds, or -1.
 */
int ngtcp2_crypto_hp_mask(uint8_t *dest,
                                        const ngtcp2_crypto_cipher *hp,
                                        const ngtcp2_crypto_cipher_ctx *hp_ctx,
                                        const uint8_t *sample);
|#

(define-ngc ngtcp2_crypto_hp_mask_cb _fpointer)

#|
/**
 * @function
 *
 * `ngtcp2_crypto_derive_and_install_rx_key` derives the rx keys from
 * |secret| and installs new keys to |conn|.
 *
 * If |key| is not NULL, the derived packet protection key for
 * decryption is written to the buffer pointed by |key|.  If |iv| is
 * not NULL, the derived packet protection IV for decryption is
 * written to the buffer pointed by |iv|.  If |hp| is not NULL, the
 * derived header protection key for decryption is written to the
 * buffer pointed by |hp|.
 *
 * |secretlen| specifies the length of |secret|.
 *
 * The length of packet protection key and header protection key is
 * `ngtcp2_crypto_aead_keylen(ctx->aead) <ngtcp2_crypto_aead_keylen>`,
 * and the length of packet protection IV is
 * `ngtcp2_crypto_packet_protection_ivlen(ctx->aead)
 * <ngtcp2_crypto_packet_protection_ivlen>` where ctx is obtained by
 * `ngtcp2_crypto_ctx_tls` (or `ngtcp2_crypto_ctx_tls_early` if
 * |level| == :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`).
 *
 * In the first call of this function, it calls
 * `ngtcp2_conn_set_crypto_ctx` (or `ngtcp2_conn_set_early_crypto_ctx`
 * if |level| ==
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`) to set
 * negotiated AEAD and message digest algorithm.  After the successful
 * call of this function, application can use
 * `ngtcp2_conn_get_crypto_ctx` (or `ngtcp2_conn_get_early_crypto_ctx`
 * if |level| ==
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`) to get
 * :type:`ngtcp2_crypto_ctx`.
 *
 * If |conn| is initialized as client, and |level| is
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_APPLICATION`, this
 * function retrieves a remote QUIC transport parameters extension
 * from an object obtained by `ngtcp2_conn_get_tls_native_handle` and
 * sets it to |conn| by calling
 * `ngtcp2_conn_set_remote_transport_params`.
 *
 * This function returns 0 if it succeeds, or -1.
 */
int ngtcp2_crypto_derive_and_install_rx_key(
    ngtcp2_conn *conn, uint8_t *key, uint8_t *iv, uint8_t *hp,
    ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
|#

#|
/**
 * @function
 *
 * `ngtcp2_crypto_derive_and_install_tx_key` derives the tx keys from
 * |secret| and installs new keys to |conn|.
 *
 * If |key| is not NULL, the derived packet protection key for
 * encryption is written to the buffer pointed by |key|.  If |iv| is
 * not NULL, the derived packet protection IV for encryption is
 * written to the buffer pointed by |iv|.  If |hp| is not NULL, the
 * derived header protection key for encryption is written to the
 * buffer pointed by |hp|.
 *
 * |secretlen| specifies the length of |secret|.
 *
 * The length of packet protection key and header protection key is
 * `ngtcp2_crypto_aead_keylen(ctx->aead) <ngtcp2_crypto_aead_keylen>`,
 * and the length of packet protection IV is
 * `ngtcp2_crypto_packet_protection_ivlen(ctx->aead)
 * <ngtcp2_crypto_packet_protection_ivlen>` where ctx is obtained by
 * `ngtcp2_crypto_ctx_tls` (or `ngtcp2_crypto_ctx_tls_early` if
 * |level| == :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`).
 *
 * In the first call of this function, it calls
 * `ngtcp2_conn_set_crypto_ctx` (or `ngtcp2_conn_set_early_crypto_ctx`
 * if |level| ==
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`) to set
 * negotiated AEAD and message digest algorithm.  After the successful
 * call of this function, application can use
 * `ngtcp2_conn_get_crypto_ctx` (or `ngtcp2_conn_get_early_crypto_ctx`
 * if |level| ==
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_EARLY`) to get
 * :type:`ngtcp2_crypto_ctx`.
 *
 * If |conn| is initialized as server, and |level| is
 * :enum:`ngtcp2_crypto_level.NGTCP2_CRYPTO_LEVEL_APPLICATION`, this
 * function retrieves a remote QUIC transport parameters extension
 * from an object obtained by `ngtcp2_conn_get_tls_native_handle` and
 * sets it to |conn| by calling
 * `ngtcp2_conn_set_remote_transport_params`.
 *
 * This function returns 0 if it succeeds, or -1.
 */
int ngtcp2_crypto_derive_and_install_tx_key(
    ngtcp2_conn *conn, uint8_t *key, uint8_t *iv, uint8_t *hp,
    ngtcp2_crypto_level level, const uint8_t *secret, size_t secretlen);
|#

#|
/**
 * @function
 *
 * `ngtcp2_crypto_update_key` updates traffic keying materials.
 *
 * The new traffic secret for decryption is written to the buffer
 * pointed by |rx_secret|.  The length of secret is |secretlen| bytes,
 * and |rx_secret| must point to the buffer which has enough capacity.
 *
 * The new traffic secret for encryption is written to the buffer
 * pointed by |tx_secret|.  The length of secret is |secretlen| bytes,
 * and |tx_secret| must point to the buffer which has enough capacity.
 *
 * The derived packet protection key for decryption is written to the
 * buffer pointed by |rx_key|.  The derived packet protection IV for
 * decryption is written to the buffer pointed by |rx_iv|.
 * |rx_aead_ctx| must be constructed with |rx_key|.
 *
 * The derived packet protection key for encryption is written to the
 * buffer pointed by |tx_key|.  The derived packet protection IV for
 * encryption is written to the buffer pointed by |tx_iv|.
 * |tx_aead_ctx| must be constructed with |rx_key|.
 *
 * |current_rx_secret| and |current_tx_secret| are the current traffic
 * secrets for decryption and encryption.  |secretlen| specifies the
 * length of |rx_secret| and |tx_secret|.
 *
 * The length of packet protection key and header protection key is
 * `ngtcp2_crypto_aead_keylen(ctx->aead) <ngtcp2_crypto_aead_keylen>`,
 * and the length of packet protection IV is
 * `ngtcp2_crypto_packet_protection_ivlen(ctx->aead)
 * <ngtcp2_crypto_packet_protection_ivlen>` where ctx is obtained by
 * `ngtcp2_crypto_ctx_tls`.
 *
 * This function returns 0 if it succeeds, or -1.
 */
int ngtcp2_crypto_update_key(
    ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
    ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_key, uint8_t *rx_iv,
    ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_key, uint8_t *tx_iv,
    const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
    size_t secretlen);
|#

(define-ngc ngtcp2_crypto_update_key_cb _fpointer)
(define-ngc ngtcp2_crypto_client_initial_cb _fpointer)
(define-ngc ngtcp2_crypto_recv_retry_cb _fpointer)
(define-ngc ngtcp2_crypto_recv_client_initial_cb _fpointer)

(define-ngc ngtcp2_crypto_read_write_crypto_data
  (_fun [conn : _ngtcp2_conn*]
        [crypto_level : _ngtcp2_crypto_level]
        [data : #;const _pointer]
        [datalen : _size]
        -> _int))

(define-ngc ngtcp2_crypto_recv_crypto_data_cb _fpointer)

(define-ngc ngtcp2_crypto_generate_stateless_reset_token
  (_fun [token : _pointer = (make-bytes NGTCP2_STATELESS_RESET_TOKENLEN)]
        [md : #;const _ngtcp2_crypto_md*]
        [secret : _pointer]
        [secretlen : _size]
        [cid : #;const _ngtcp2_cid]
        -> (r : _int)
        -> (if (zero? r) token #f)))

(define-ngc ngtcp2_crypto_write_connection_close
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [version : _uint32]
        [dcid : #;const _ngtcp2_cid*]
        [scid : #;const _ngtcp2_cid*]
        [error_code : _uint64]
        -> _ngtcp2_ssize))

(define-ngc ngtcp2_crypto_write_retry
  (_fun [dest : _bytes]
        [destlen : _size = (bytes-length dest)]
        [version : _uint32]
        [dcid : #;const _ngtcp2_cid*]
        [scid : #;const _ngtcp2_cid*]
        [odcid : #;const _ngtcp2_cid*]
        [token : _bytes]
        [tokenlen : _size = (bytes-length token)]
        -> _ngtcp2_ssize))

(define-ngc ngtcp2_crypto_aead_ctx_encrypt_init
  (_fun [aead_ctx : _ngtcp2_crypto_aead_ctx*]
        [aead : #;const _ngtcp2_crypto_aead*]
        [key : _pointer]
        [noncelen : _size]
        -> _int))

(define-ngc ngtcp2_crypto_aead_ctx_decrypt_init
  (_fun [aead_ctx : _ngtcp2_crypto_aead_ctx*]
        [aead : #;const _ngtcp2_crypto_aead*]
        [key : _pointer]
        [noncelen : _size]
        -> _int))

(define-ngc ngtcp2_crypto_aead_ctx_free
  (_fun [aead_ctx : _ngtcp2_crypto_aead_ctx*]
        -> _void))

(define-ngc ngtcp2_crypto_delete_crypto_aead_ctx_cb _fpointer)
(define-ngc ngtcp2_crypto_delete_crypto_cipher_ctx_cb _fpointer)
