;; Secure Authorization Test Fixture (Clarity / Stacks)
;; Intent Security Workbench - Phase 5
;; Controlled Test Principals: Strictly labeled TEST_FIXTURE

(define-map balances principal uint)

(define-public (deposit (amount uint))
  (let ((current (default-to u0 (map-get? balances tx-sender))))
    (map-set balances tx-sender (+ current amount))
    (ok true)))

;; SECURE: Caller must match owner principal
(define-public (redeem (owner principal) (amount uint))
  (let (
    (owner-balance (default-to u0 (map-get? balances owner)))
    (caller-balance (default-to u0 (map-get? balances tx-sender)))
  )
    (asserts! (is-eq tx-sender owner) (err u401)) ;; UNAUTHORIZED
    (asserts! (>= owner-balance amount) (err u400))
    (map-set balances owner (- owner-balance amount))
    (map-set balances tx-sender (+ caller-balance amount))
    (ok true)))
