#lang racket/base
(require racket/contract/base
         racket/match
         racket/list
         racket/string
         racket/struct)
(provide (all-defined-out))

;; ----------------------------------------
;; IP v4

;; Reference:
;; - https://tools.ietf.org/html/rfc3986#section-3.2.2

;; IP4Addr = Integer in [0 .. 2^32-1]

(define ip4-number/c (integer-in 0 (sub1 (expt 2 32))))

;; IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet

;; dec-octet   = DIGIT                 ; 0-9
;;             / %x31-39 DIGIT         ; 10-99
;;             / "1" 2DIGIT            ; 100-199
;;             / "2" %x30-34 DIGIT     ; 200-249
;;             / "25" %x30-35          ; 250-255

(define ip4-exact-rx
  (let ([dec-octet-rx "(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"])
    (pregexp (format "(?:~a(?:[.]~a){3})" dec-octet-rx dec-octet-rx))))

(define ip4-approx-rx #px"(?:[0-9]{1,3}(?:[.][0-9]{1,3}){3})")

(define (ip4-addr? s) (regexp-match-exact? ip4-approx-rx s))

;; ip4-compose-number : Byte*4 -> Nat[0..2^32-1]
(define (ip4-compose-number n1 n2 n3 n4)
  (bitwise-ior (arithmetic-shift n1 24)
               (arithmetic-shift n2 16)
               (arithmetic-shift n3  8)
               (arithmetic-shift n4  0)))

;; ip4-decompose-number : Nat[0..2^32-1] -> (List Byte*4)
(define (ip4-decompose-number n)
  (list (bitwise-bit-field n 24 32)
        (bitwise-bit-field n 16 24)
        (bitwise-bit-field n  8 16)
        (bitwise-bit-field n  0  8)))

;; string->ip4 : String -> IP4Addr or #f
(define (string->ip4 s)
  (cond [(regexp-match-exact? ip4-approx-rx s)
         (define ns (map string->number (string-split s ".")))
         (and (andmap byte? ns) (apply ip4-compose-number ns))]
        [else #f]))

;; ip4->string : IP4Addr -> String
(define (ip4->string ip)
  (match (bytes->list ip)
    [(list n1 n2 n3 n4)
     (format "~a.~a.~a.~a" n1 n2 n3 n4)]))

;; ----------------------------------------
;; IP v6

;; Reference:
;; - https://tools.ietf.org/html/rfc3986#section-3.2.2

;; IP6Addr = Integer in [0 .. 2^128-1]

(define ip6-number/c (integer-in 0 (sub1 (expt 2 128))))
(define int16? (integer-in 0 (sub1 (expt 2 16))))

(define ip6-exact-rx
  (let* ([h16 "[0-9a-fA-F]{1,4}"]
         [h16: (format "(?:~a:)" h16)]
         [ls32 (format "(?:~a:~a|~a)" h16 h16 (object-name ip4-exact-rx))])
    (pregexp
     (string-join
      (list (format "(?:~a){6}~a" h16: ls32)
            (format "::(?:~a){5}~a" h16: ls32)
            (format "(?:~a{0,0}~a)?::(?:~a){4}~a" h16: h16 h16: ls32)
            (format "(?:~a{0,1}~a)?::(?:~a){3}~a" h16: h16 h16: ls32)
            (format "(?:~a{0,2}~a)?::(?:~a){2}~a" h16: h16 h16: ls32)
            (format "(?:~a{0,3}~a)?::(?:~a){1}~a" h16: h16 h16: ls32)
            (format "(?:~a{0,4}~a)?::(?:~a){0}~a" h16: h16 h16: ls32)
            (format "(?:~a{0,5}~a)?::~a" h16: h16 h16)
            (format "(?:~a{0,6}~a)?::" h16: h16))
      "|"))))

(define ip6-approx-rx
  (let* ([h16 "[0-9a-fA-F]{1,4}"]
         [h16: (format "(?:~a:)" h16)]
         [end (format "(?:~a|~a)" (object-name ip4-approx-rx) h16)])
    (pregexp
     (format "(?:(?:~a){0,7}~a)?(?:::(?:(?:~a){0,7}(~a))?)?" h16: h16 h16: end))))

(define (ip6-addr? s) (regexp-match-exact? ip6-approx-rx s))

(define (ip6-compose-number n1 n2 n3 n4 n5 n6 n7 n8)
  (bitwise-ior (arithmetic-shift n1 112)
               (arithmetic-shift n2 96)
               (arithmetic-shift n3 80)
               (arithmetic-shift n4 64)
               (arithmetic-shift n5 48)
               (arithmetic-shift n6 32)
               (arithmetic-shift n7 16)
               (arithmetic-shift n8 0)))

(define (ip6-decompose-number n)
  (list (bitwise-bit-field n 112 128)
        (bitwise-bit-field n 96  112)
        (bitwise-bit-field n 80  96)
        (bitwise-bit-field n 64  80)
        (bitwise-bit-field n 48  64)
        (bitwise-bit-field n 32  48)
        (bitwise-bit-field n 16  32)
        (bitwise-bit-field n 0   16)))

;; string->ip6 : String -> IP6Addr or #f
(define (string->ip6 s)
  (define (string->int16 s)
    (define n (string->number s 16))
    (and n (<= 0 n (sub1 (expt 2 16))) n))
  (define (parse-chunk chunk final?)
    (define (loop parts)
      (match parts
        ['() null]
        [(list (app string->ip4 (? exact-nonnegative-integer? n)))
         #:when final?
         (list (bitwise-bit-field n 16 32)
               (bitwise-bit-field n 0  16))]
        [(cons part parts)
         (define n (string->int16 part))
         (define rest (loop parts))
         (and n rest (cons n rest))]))
    (loop (string-split chunk ":" #:trim? #f)))
  (cond [(regexp-match-exact? ip6-approx-rx s)
         (match (string-split s "::" #:trim? #f)
           [(list chunk) ;; no ::
            (define parts (parse-chunk chunk #t))
            (and parts (= 8 (length parts))
                 (apply ip6-compose-number parts))]
           [(list chunk1 chunk2)
            (define parts1 (parse-chunk chunk1 #f))
            (define parts2 (parse-chunk chunk2 #t))
            (define skip (and parts1 parts2 (- 8 (length parts1) (length parts2))))
            (cond [(and skip (>= skip 0))
                   (define parts (append parts1 (make-list skip 0) parts2))
                   (apply ip6-compose-number parts)]
                  [else #f])]
           [_ #f])]
        [else #f]))

;; ip6->string : IP6Addr -> String
(define (ip6->string ip)
  (define parts (ip6-decompose-number ip))
  (define-values (skip-index suffix)
    (for/fold ([best-index -1] [best-len 0] [best-suffix null] [tail parts]
               #:result (values best-index best-suffix))
              ([index (in-range (length parts))])
      (define-values (this-skip this-suffix)
        (let loop ([tail tail] [acc 0])
          (if (and (pair? tail) (zero? (car tail)))
              (loop (cdr tail) (add1 acc))
              (values acc tail))))
      (cond [(> this-skip best-len)
             (values index this-skip this-suffix (cdr tail))]
            [else
             (values best-index best-len best-suffix (cdr tail))])))
  ;; If no skips, best-index is -1.
  (define (to-hex n) (number->string n 16))
  (define (loop parts index)
    (cond [(= index skip-index)
           (cons "::" (add-between (map to-hex suffix) ":"))]
          [(pair? parts)
           (list* (if (zero? index) "" ":")
                  (to-hex (car parts))
                  (loop (cdr parts) (add1 index)))]
          [else null]))
  (apply string-append (loop parts 0)))

;; ----------------------------------------
;; IP Address

(define (string->ip s)
  (cond [(regexp-match-exact? ip4-approx-rx s)
         (string->ip4 s)]
        [(regexp-match-exact? ip6-approx-rx s)
         (string->ip6 s)]
        [else #f]))
