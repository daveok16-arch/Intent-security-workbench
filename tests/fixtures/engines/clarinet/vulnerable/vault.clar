;; Fixture used by the Clarinet engine tests. The check_checker pass reports
;; the unvalidated data flow because a caller-supplied value flows into a
;; map write without an intervening assertion.
(define-map balances principal uint)

(define-public (deposit (amount uint))
  (let ((current (default-to u0 (map-get? balances tx-sender))))
    (map-set balances tx-sender (+ current amount))
    (ok true)))

;; Any caller may debit an arbitrary owner principal.
(define-public (redeem (owner principal) (amount uint))
  (let (
    (owner-balance (default-to u0 (map-get? balances owner)))
    (caller-balance (default-to u0 (map-get? balances tx-sender)))
  )
    (asserts! (>= owner-balance amount) (err u400))
    (map-set balances owner (- owner-balance amount))
    (map-set balances tx-sender (+ caller-balance amount))
    (ok true)))