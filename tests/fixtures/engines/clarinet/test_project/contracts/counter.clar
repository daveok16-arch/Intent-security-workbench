;; Simple Clarity Counter Contract
(define-data-var count int 0)

(define-read-only (get-count)
  (ok (var-get count)))

(define-public (increment)
  (begin
    (var-set count (+ (var-get count) 1))
    (ok (var-get count))))

(define-public (decrement)
  (begin
    (var-set count (- (var-get count) 1))
    (ok (var-get count))))
