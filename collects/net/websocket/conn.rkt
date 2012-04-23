#lang racket
(require web-server/http/request-structs)

(define framing-mode (make-parameter 'old))
(define (framing-for ver)
  (case ver
    [(rfc6455) 'rfc6455]
    [else 'old]))

(struct ws-conn ([closed? #:mutable] line headers ip op version)
        #:property prop:evt (struct-field-index ip))
(define (open-ws-conn? x)
  (and (ws-conn? x) (not (ws-conn-closed? x))))
(provide/contract
 [framing-mode (parameter/c (symbols 'old 'new 'rfc6455))]
 [ws-conn (false/c bytes? (listof header?) input-port? output-port? framing-mode . -> . open-ws-conn?)]
 [ws-conn? (any/c . -> . boolean?)]
 [open-ws-conn? (any/c . -> . boolean?)]
 [ws-conn-line (ws-conn? . -> . bytes?)]
 [ws-conn-closed? (ws-conn? . -> . boolean?)]
 [ws-conn-headers (ws-conn? . -> . (listof header?))]
 [ws-send! (-> ws-conn? (or/c string? bytes?) void)]
 [ws-recv (-> ws-conn? (or/c string? eof-object?))]
 [ws-close! (-> ws-conn? void)])

(define (make-rfc6455-frame opcode payload final-fragment?)
  (define len (string-length payload))
  (define len-bs
    (cond ((> 126 len) (bytes len))
          ((> 65536 len)
           (bytes-append (bytes 126)
                         (integer->integer-bytes len 2 #f)))
          ((> 4294967296 len)
           (bytes-append (bytes 127)
                         (integer->integer-bytes len 4 #f)))
          (else (error 'make-rfc6455-frame "payload is too long to encode"))))

  (define header0 (bitwise-ior (if final-fragment? #x80 #x00)
                               (case opcode
                                 [(continutation) 0]
                                 [(text) 1]
                                 [(binary) 2]
                                 [(close) 8]
                                 [(ping) 9]
                                 [(pong) 10])))
  
  (bytes-append (bytes header0) len-bs
                (if (string? payload) (string->bytes/utf-8 payload)
                    payload)))
                
(define (write-ws-frame! type string op)
  (define bs (string->bytes/utf-8 string))
  (case (framing-mode)
    [(rfc6455)
     (printf "write-ws-frame rfc6455\n")(flush-output)
     (write-bytes (make-rfc6455-frame type string #t) op)
     ]
    [(new)
     (write-byte (case type [(text binary) #xFF] [(close) #x00]) op)
     (write-bytes (integer->integer-bytes (bytes-length bs) 8 #f #t) op)
     (write-bytes bs op)]
    [(old)
     (write-byte #x00 op)
     (write-bytes bs op)
     (write-byte #xff op)])
  (flush-output op))  

(define (read-non-eof-bytes len ip)
  (let ([bytes (read-bytes len ip)])
    (when (eof-object? bytes)
      (error 'read-ws-frame "Premature connection close"))
    bytes))

(define (read-ws-frame-rfc6455 ip)
  ;(printf "read-ws-frame-rfc6455\n")(flush-output)
  (define header0  (bytes-ref (read-non-eof-bytes 1 ip) 0))
  ;(printf "header0 ~a\n" header0)(flush-output)
  (define final    (< 0 (bitwise-and #x80 header0)))
  ;(printf "final ~a\n" final)(flush-output)
  (define ext      (bitwise-and #x70 header0))
  ;(printf "ext ~a\n" ext)(flush-output)
  (when (< 0 ext)
    (error 'read-ws-frame (format "Unknown frame extension specified: ~a" ext)))
  (define opcode   (case (bitwise-and #x07 header0)
                     [(0) 'continutation]
                     [(1) 'text]
                     [(2) 'binary]
                     [(8) 'close]
                     [(9) 'ping]
                     [(10) 'pong]))
  ;(printf "opcode ~a\n" opcode)(flush-output)
  (define header1  (bytes-ref (read-non-eof-bytes 1 ip) 0))
  ;(printf "header1 ~a\n" header1)(flush-output)
  (define has-mask (< 0 (bitwise-and #x80 header1)))
  ;(printf "has-mask ~a\n" has-mask)(flush-output)
  (define length0  (bitwise-and #x7F header1))
  ;(printf "length0 ~a\n" length0)(flush-output)
  (define length
    (cond ((> 126 length0) length0)
          ((= 126 length0) (integer-bytes->integer (read-non-eof-bytes 2 ip) #f))
          ((= 127 length0) (integer-bytes->integer (read-non-eof-bytes 4 ip) #f))
          (else 'huh)))
  ;(printf "length ~a\n" length)(flush-output)
  (define mask     (when has-mask (read-non-eof-bytes 4 ip)))
  ;(printf "mask ~a\n" mask)(flush-output)
  (define payload  (read-non-eof-bytes length ip))
  ;(printf "payload ~a\n" payload)(flush-output)
  (define app-data payload)
  ;(printf "app-data ~a\n" app-data)(flush-output)
  
  (when has-mask
    (for ([ i (in-range (bytes-length app-data))])
         (bytes-set! app-data i
                     (bitwise-xor (bytes-ref mask (modulo i 4))
                                  (bytes-ref app-data i)))))
  
  ;(printf "return ~a / ~a\n" opcode app-data)(flush-output)
  (values opcode (bytes->string/utf-8 app-data)))

(define (read-ws-frame ip)
  (case (framing-mode)
    [(rfc6455) (read-ws-frame-rfc6455 ip)]
    [(new)
     (let ()
       (define frame (read-byte ip))
       (when (eof-object? frame) (error 'read-ws-frame "Premature connection close"))
       (define len-bs (read-bytes 8 ip))
       (when (eof-object? len-bs) (error 'read-ws-frame "Premature connection close"))
       (define len (integer-bytes->integer len-bs #f #t))
       (define data-bs (read-bytes len ip))
       (when (eof-object? data-bs) (error 'read-ws-frame "Premature connection close"))
       (values frame (bytes->string/utf-8 data-bs)))]
    [(old)
     (let ()
       (define l (read-byte ip))
       (cond [(eof-object? l) (values #x00 #"")]
             [(= #xff l)
              (read-byte ip)
              (values #x00 #"")]
             [else
              (values #xff (bytes->string/utf-8 (read-until-byte #xff ip)))]))]))

(define (read-until-byte b ip)
  (define ob (open-output-bytes))
  (let loop ()
    (define n (read-byte ip))
    (unless (or (eof-object? n) (= n b))
      (write-byte n ob)
      (loop)))
  (get-output-bytes ob))

(define (ws-send! wsc s)
  (match-define (ws-conn _ _ _ _ op ver) wsc)
  (parameterize ([framing-mode (framing-for ver)])
    (define type (cond ((string? s) 'text)
                       ((bytes? s) 'binary)
                       (else 'binary)))
    (write-ws-frame! type s op)))

(define (ws-recv wsc)
  (printf "ws-recv\n")
  (match-define (ws-conn _ _ _ ip _ ver) wsc)
  (parameterize ([framing-mode (framing-for ver)])
    (define-values (ft m) (read-ws-frame ip))
    (printf "ws-recv read ft ~a\n" ft)
    (case (framing-mode)
      [(rfc6455)
       (case ft
         [(text binary) m]
         [(continutation) ""]
         [(close) eof]
         [(ping pong) ""]
         [else ""])]
      
      [else 
       (if (= #x00 ft)
           eof
           m)])))
  
(define (ws-close! wsc)
  (match-define (ws-conn _ _ _ ip op ver) wsc)
  (parameterize ([framing-mode (framing-for ver)])
    
    (case (framing-mode)
      [(new)
       (write-ws-frame! 'close "" op)]
      [(old)
       (write-byte #xff op)
       (write-byte #x00 op)
       (flush-output op)])
    
    (close-input-port ip)
    (close-output-port op)
    (set-ws-conn-closed?! wsc #t)))
  