#lang info
;; Husk test fixture: a Racket package's root info.rkt (raco pkg metadata).
;; Intentionally exercises every dependency shape the parser handles.

(define collection "widget-lib")
(define version "1.4.2")

#| block comment: the deps below mix bare names, #:version floors,
   the deprecated two-string form, and a quasiquoted ,version unquote. |#

(define deps
  `("racket-lib"           ; bare name, no version
    "base"                 ; bare name, no version
    ("rackunit-lib" #:version "1.11")   ; pinned floor
    ["draw-lib" "1.18"]                 ; deprecated (name version)
    ["racket" #:version ,version]       ; unquote -> 1.4.2
    ("net-lib" #:platform "x86_64-linux" #:version "1.7")))

(define build-deps
  '("scribble-lib"
    ("rackunit-typed" #:version "1.2")))

(define pkg-desc "A widget library for testing Husk's Racket target")
(define pkg-authors '(jane))
