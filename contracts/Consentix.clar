(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_CONSENT_NOT_FOUND (err u101))
(define-constant ERR_CONSENT_EXPIRED (err u102))
(define-constant ERR_CONSENT_REVOKED (err u103))
(define-constant ERR_INVALID_DURATION (err u104))
(define-constant ERR_ALREADY_EXISTS (err u105))
(define-constant ERR_INVALID_PRINCIPAL (err u106))

(define-map consents
  { grantor: principal, grantee: principal, resource-id: (string-ascii 64) }
  {
    granted-at: uint,
    expires-at: uint,
    is-active: bool,
    permissions: (list 10 (string-ascii 32)),
    metadata: (string-ascii 256)
  }
)

(define-map user-consent-count principal uint)

(define-map resource-permissions
  (string-ascii 64)
  {
    owner: principal,
    required-permissions: (list 10 (string-ascii 32)),
    is-public: bool
  }
)

(define-data-var total-consents uint u0)
(define-data-var contract-paused bool false)

(define-public (grant-consent 
  (grantee principal) 
  (resource-id (string-ascii 64)) 
  (duration uint) 
  (permissions (list 10 (string-ascii 32)))
  (metadata (string-ascii 256)))
  (let (
    (consent-key { grantor: tx-sender, grantee: grantee, resource-id: resource-id })
    (current-block stacks-block-height)
    (expiry-block (+ current-block duration))
  )
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    (asserts! (> duration u0) ERR_INVALID_DURATION)
    (asserts! (not (is-eq tx-sender grantee)) ERR_INVALID_PRINCIPAL)
    (asserts! (is-none (map-get? consents consent-key)) ERR_ALREADY_EXISTS)
    
    (map-set consents consent-key {
      granted-at: current-block,
      expires-at: expiry-block,
      is-active: true,
      permissions: permissions,
      metadata: metadata
    })
    
    (map-set user-consent-count grantee 
      (+ (default-to u0 (map-get? user-consent-count grantee)) u1))
    
    (var-set total-consents (+ (var-get total-consents) u1))
    (ok true)
  )
)

(define-public (revoke-consent 
  (grantee principal) 
  (resource-id (string-ascii 64)))
  (let (
    (consent-key { grantor: tx-sender, grantee: grantee, resource-id: resource-id })
    (consent-data (unwrap! (map-get? consents consent-key) ERR_CONSENT_NOT_FOUND))
  )
    (asserts! (get is-active consent-data) ERR_CONSENT_REVOKED)
    
    (map-set consents consent-key 
      (merge consent-data { is-active: false }))
    
    (map-set user-consent-count grantee 
      (- (default-to u1 (map-get? user-consent-count grantee)) u1))
    
    (ok true)
  )
)

(define-public (extend-consent 
  (grantee principal) 
  (resource-id (string-ascii 64)) 
  (additional-duration uint))
  (let (
    (consent-key { grantor: tx-sender, grantee: grantee, resource-id: resource-id })
    (consent-data (unwrap! (map-get? consents consent-key) ERR_CONSENT_NOT_FOUND))
    (new-expiry (+ (get expires-at consent-data) additional-duration))
  )
    (asserts! (> additional-duration u0) ERR_INVALID_DURATION)
    (asserts! (get is-active consent-data) ERR_CONSENT_REVOKED)
    (asserts! (> (get expires-at consent-data) stacks-block-height) ERR_CONSENT_EXPIRED)
    
    (map-set consents consent-key 
      (merge consent-data { expires-at: new-expiry }))
    
    (ok true)
  )
)

(define-public (register-resource 
  (resource-id (string-ascii 64)) 
  (required-permissions (list 10 (string-ascii 32))) 
  (is-public bool))
  (begin
    (asserts! (is-none (map-get? resource-permissions resource-id)) ERR_ALREADY_EXISTS)
    
    (map-set resource-permissions resource-id {
      owner: tx-sender,
      required-permissions: required-permissions,
      is-public: is-public
    })
    
    (ok true)
  )
)

(define-public (update-resource-permissions 
  (resource-id (string-ascii 64)) 
  (new-permissions (list 10 (string-ascii 32))))
  (let (
    (resource-data (unwrap! (map-get? resource-permissions resource-id) ERR_CONSENT_NOT_FOUND))
  )
    (asserts! (is-eq tx-sender (get owner resource-data)) ERR_UNAUTHORIZED)
    
    (map-set resource-permissions resource-id 
      (merge resource-data { required-permissions: new-permissions }))
    
    (ok true)
  )
)

(define-public (pause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-paused true)
    (ok true)
  )
)

(define-public (unpause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-paused false)
    (ok true)
  )
)

(define-read-only (check-consent 
  (grantor principal) 
  (grantee principal) 
  (resource-id (string-ascii 64)))
  (let (
    (consent-key { grantor: grantor, grantee: grantee, resource-id: resource-id })
    (consent-data (map-get? consents consent-key))
  )
    (match consent-data
      consent-info
        (and 
          (get is-active consent-info)
          (> (get expires-at consent-info) stacks-block-height))
      false
    )
  )
)

(define-read-only (get-consent-details 
  (grantor principal) 
  (grantee principal) 
  (resource-id (string-ascii 64)))
  (let (
    (consent-key { grantor: grantor, grantee: grantee, resource-id: resource-id })
  )
    (map-get? consents consent-key)
  )
)

(define-read-only (has-permission 
  (grantor principal) 
  (grantee principal) 
  (resource-id (string-ascii 64)) 
  (required-permission (string-ascii 32)))
  (let (
    (consent-key { grantor: grantor, grantee: grantee, resource-id: resource-id })
    (consent-data (map-get? consents consent-key))
  )
    (match consent-data
      consent-info
        (and 
          (get is-active consent-info)
          (> (get expires-at consent-info) stacks-block-height)
          (is-some (index-of (get permissions consent-info) required-permission)))
      false
    )
  )
)

(define-read-only (get-user-consent-count (user principal))
  (default-to u0 (map-get? user-consent-count user))
)

(define-read-only (get-resource-info (resource-id (string-ascii 64)))
  (map-get? resource-permissions resource-id)
)

(define-read-only (get-total-consents)
  (var-get total-consents)
)

(define-read-only (is-contract-paused)
  (var-get contract-paused)
)

(define-read-only (get-contract-owner)
  CONTRACT_OWNER
)

(define-read-only (is-consent-expired 
  (grantor principal) 
  (grantee principal) 
  (resource-id (string-ascii 64)))
  (let (
    (consent-key { grantor: grantor, grantee: grantee, resource-id: resource-id })
    (consent-data (map-get? consents consent-key))
  )
    (match consent-data
      consent-info
        (<= (get expires-at consent-info) stacks-block-height)
      true
    )
  )
)

(define-read-only (get-consent-time-remaining 
  (grantor principal) 
  (grantee principal) 
  (resource-id (string-ascii 64)))
  (let (
    (consent-key { grantor: grantor, grantee: grantee, resource-id: resource-id })
    (consent-data (map-get? consents consent-key))
  )
    (match consent-data
      consent-info
        (if (> (get expires-at consent-info) stacks-block-height)
          (some (- (get expires-at consent-info) stacks-block-height))
          (some u0))
      none
    )
  )
)