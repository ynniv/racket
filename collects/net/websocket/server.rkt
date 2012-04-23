#lang racket
(require web-server/private/dispatch-server-unit
         web-server/private/dispatch-server-sig
         web-server/private/connection-manager
         web-server/http/response
         web-server/http/request
         web-server/http/request-structs
         racket/async-channel
         unstable/contract
         net/base64
         net/tcp-sig
         openssl/sha1
         (prefix-in raw: net/tcp-unit)
         net/websocket/conn
         net/websocket/handshake)
(provide (except-out (all-from-out net/websocket/conn) ws-conn))

(provide/contract
 [ws-serve
  (->* ((open-ws-conn? any/c . -> . void))
       (#:conn-headers 
        (bytes? (listof header?) . -> . (values (listof header?) any/c))
        #:tcp@
        (unit/c (import) (export tcp^))
        #:port
        tcp-listen-port?
        #:listen-ip
        (or/c string? false/c)
        #:max-waiting
        integer?
        #:timeout
        integer?
        #:confirmation-channel
        (or/c false/c async-channel?))
       (-> void))])

(define (ws-serve conn-dispatch
                  #:conn-headers [pre-conn-dispatch (λ (cline hs) (values empty (void)))]
                  #:tcp@ [tcp@ raw:tcp@]
                  #:port [port 80]
                  #:listen-ip [listen-ip #f]
                  #:max-waiting [max-waiting 4]
                  #:timeout [initial-connection-timeout (* 60 60)]
                  #:confirmation-channel [confirm-ch #f])
  (define (read-request c p port-addresses)
    (values #f #t))
  (define (dispatch c _)
    (define ip (connection-i-port c))
    (define op (connection-o-port c))
    (define cline (read-bytes-line ip 'any))
    (define headers (read-headers ip))
    (define client-version (headers-assq* #"Sec-WebSocket-Version" headers))

    (define (dispatch-hixie)
      (define key1h (headers-assq* #"Sec-WebSocket-Key1" headers))
      (unless key1h (error 'ws-serve "Invalid WebSocket request, no Key1"))
      (define key1 (header-value key1h))
      (define key2h (headers-assq* #"Sec-WebSocket-Key2" headers))
      (unless key2h (error 'ws-serve "Invalid WebSocket request, no Key2"))
      (define key2 (header-value key2h))
      (define key3 (read-bytes 8 ip))
      
      (define-values (conn-headers state) (pre-conn-dispatch cline headers))
      
      (fprintf op "HTTP/1.1 101 WebSocket Protocol Handshake\r\n")
      (print-headers 
       op
       (list* (make-header #"Upgrade" #"WebSocket")
              (make-header #"Connection" #"Upgrade")
              conn-headers))
      
      (write-bytes
       (handshake-solution (bytes->string/utf-8 key1)
                           (bytes->string/utf-8 key2)
                           key3)
       op)
      (flush-output op)
      
      (define conn
        (ws-conn #f cline conn-headers ip op 'hixie))
      
      (conn-dispatch conn state))
    
    (define (dispatch-rfc6455)
      (define keyh (headers-assq* #"Sec-WebSocket-Key" headers))
      (unless keyh (error 'ws-serve "Invalid WebSocket request, no Key"))
      (define key  (header-value keyh))
      (define magic #"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      (define key-magic-port (open-input-string (format "~a~a" key magic)))
      (define key-magic-hash (base64-encode (sha1-bytes key-magic-port) ""))
      
      (define-values (conn-headers state) (pre-conn-dispatch cline headers))
      
      (fprintf op "HTTP/1.1 101 Switching Protocols\r\n")
      (print-headers
       op
       (list* (make-header #"Upgrade" #"WebSocket")
              (make-header #"Connection" #"Upgrade")
              (make-header #"Sec-WebSocket-Accept" key-magic-hash)
              conn-headers))
      
      (flush-output op)
      
      (define conn
        (ws-conn #f cline conn-headers ip op 'rfc6455))
      
      (conn-dispatch conn state))

    (if client-version
        (dispatch-rfc6455)
        (dispatch-hixie)))
  
  (define-unit-binding a-tcp@
    tcp@ (import) (export tcp^))
  (define-compound-unit/infer dispatch-server@/tcp@
    (import dispatch-server-config^)
    (link a-tcp@ dispatch-server@)
    (export dispatch-server^))
  (define-values/invoke-unit
    dispatch-server@/tcp@
    (import dispatch-server-config^)
    (export dispatch-server^))
  (serve #:confirmation-channel confirm-ch))
