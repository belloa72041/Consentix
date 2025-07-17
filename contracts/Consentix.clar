(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_CONSENT_NOT_FOUND (err u101))
(define-constant ERR_CONSENT_EXPIRED (err u102))
(define-constant ERR_CONSENT_REVOKED (err u103))
(define-constant ERR_INVALID_DURATION (err u104))
(define-constant ERR_ALREADY_EXISTS (err u105))
(define-constant ERR_INVALID_PRINCIPAL (err u106))
(define-constant ERR_TEMPLATE_NOT_FOUND (err u107))
(define-constant ERR_TEMPLATE_EXISTS (err u108))
(define-constant ERR_INVALID_TEMPLATE (err u109))
(define-constant ERR_BATCH_LIMIT_EXCEEDED (err u110))
(define-constant ERR_BATCH_OPERATION_FAILED (err u111))
(define-constant MAX_BATCH_SIZE u50)

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
(define-data-var template-count uint u0)

(define-map consent-templates
  (string-ascii 64)
  {
    creator: principal,
    name: (string-ascii 128),
    description: (string-ascii 256),
    default-duration: uint,
    default-permissions: (list 10 (string-ascii 32)),
    is-active: bool,
    created-at: uint,
    usage-count: uint
  }
)

(define-map template-usage
  { template-id: (string-ascii 64), user: principal }
  { usage-count: uint, last-used: uint }
)

(define-map batch-operations
  uint
  {
    initiator: principal,
    operation-type: (string-ascii 32),
    total-operations: uint,
    successful-operations: uint,
    failed-operations: uint,
    started-at: uint,
    completed-at: (optional uint),
    status: (string-ascii 32)
  }
)

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

(define-public (create-consent-template
  (template-id (string-ascii 64))
  (name (string-ascii 128))
  (description (string-ascii 256))
  (default-duration uint)
  (default-permissions (list 10 (string-ascii 32))))
  (begin
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    (asserts! (> default-duration u0) ERR_INVALID_DURATION)
    (asserts! (is-none (map-get? consent-templates template-id)) ERR_TEMPLATE_EXISTS)
    (asserts! (> (len name) u0) ERR_INVALID_TEMPLATE)
    (asserts! (> (len default-permissions) u0) ERR_INVALID_TEMPLATE)

    (map-set consent-templates template-id {
      creator: tx-sender,
      name: name,
      description: description,
      default-duration: default-duration,
      default-permissions: default-permissions,
      is-active: true,
      created-at: stacks-block-height,
      usage-count: u0
    })

    (var-set template-count (+ (var-get template-count) u1))
    (ok template-id)
  )
)

(define-public (update-consent-template
  (template-id (string-ascii 64))
  (name (string-ascii 128))
  (description (string-ascii 256))
  (default-duration uint)
  (default-permissions (list 10 (string-ascii 32))))
  (let (
    (template-data (unwrap! (map-get? consent-templates template-id) ERR_TEMPLATE_NOT_FOUND))
  )
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    (asserts! (is-eq tx-sender (get creator template-data)) ERR_UNAUTHORIZED)
    (asserts! (> default-duration u0) ERR_INVALID_DURATION)
    (asserts! (> (len name) u0) ERR_INVALID_TEMPLATE)
    (asserts! (> (len default-permissions) u0) ERR_INVALID_TEMPLATE)

    (map-set consent-templates template-id
      (merge template-data {
        name: name,
        description: description,
        default-duration: default-duration,
        default-permissions: default-permissions
      }))

    (ok true)
  )
)

(define-public (deactivate-template (template-id (string-ascii 64)))
  (let (
    (template-data (unwrap! (map-get? consent-templates template-id) ERR_TEMPLATE_NOT_FOUND))
  )
    (asserts! (is-eq tx-sender (get creator template-data)) ERR_UNAUTHORIZED)
    (asserts! (get is-active template-data) ERR_INVALID_TEMPLATE)

    (map-set consent-templates template-id
      (merge template-data { is-active: false }))

    (ok true)
  )
)

(define-public (grant-consent-from-template
  (template-id (string-ascii 64))
  (grantee principal)
  (resource-id (string-ascii 64))
  (custom-metadata (optional (string-ascii 256))))
  (let (
    (template-data (unwrap! (map-get? consent-templates template-id) ERR_TEMPLATE_NOT_FOUND))
    (consent-key { grantor: tx-sender, grantee: grantee, resource-id: resource-id })
    (current-block stacks-block-height)
    (expiry-block (+ current-block (get default-duration template-data)))
    (metadata (default-to (get description template-data) custom-metadata))
    (usage-key { template-id: template-id, user: tx-sender })
    (current-usage (default-to { usage-count: u0, last-used: u0 } 
                   (map-get? template-usage usage-key)))
  )
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    (asserts! (get is-active template-data) ERR_INVALID_TEMPLATE)
    (asserts! (not (is-eq tx-sender grantee)) ERR_INVALID_PRINCIPAL)
    (asserts! (is-none (map-get? consents consent-key)) ERR_ALREADY_EXISTS)

    (map-set consents consent-key {
      granted-at: current-block,
      expires-at: expiry-block,
      is-active: true,
      permissions: (get default-permissions template-data),
      metadata: metadata
    })

    (map-set user-consent-count grantee 
      (+ (default-to u0 (map-get? user-consent-count grantee)) u1))

    (map-set consent-templates template-id
      (merge template-data { usage-count: (+ (get usage-count template-data) u1) }))

    (map-set template-usage usage-key {
      usage-count: (+ (get usage-count current-usage) u1),
      last-used: current-block
    })

    (var-set total-consents (+ (var-get total-consents) u1))
    (ok true)
  )
)

(define-private (batch-grant-consent-helper
  (grantee-resource-pair { grantee: principal, resource-id: (string-ascii 64) })
  (previous-result { successful: uint, failed: uint }))
  (let (
    (template-id "DEFAULT_BATCH")
    (template-data (unwrap! (map-get? consent-templates template-id) 
                           { successful: (get successful previous-result), 
                             failed: (+ (get failed previous-result) u1) }))
    (consent-key { grantor: tx-sender, 
                  grantee: (get grantee grantee-resource-pair), 
                  resource-id: (get resource-id grantee-resource-pair) })
    (current-block stacks-block-height)
    (expiry-block (+ current-block (get default-duration template-data)))
  )
    (if (and 
          (not (is-eq tx-sender (get grantee grantee-resource-pair)))
          (is-none (map-get? consents consent-key))
          (get is-active template-data))
      (begin
        (map-set consents consent-key {
          granted-at: current-block,
          expires-at: expiry-block,
          is-active: true,
          permissions: (get default-permissions template-data),
          metadata: (get description template-data)
        })

        (map-set user-consent-count (get grantee grantee-resource-pair)
          (+ (default-to u0 (map-get? user-consent-count (get grantee grantee-resource-pair))) u1))

        { successful: (+ (get successful previous-result) u1), 
          failed: (get failed previous-result) }
      )
      { successful: (get successful previous-result), 
        failed: (+ (get failed previous-result) u1) }
    )
  )
)

(define-public (batch-grant-consents
  (grantee-resource-pairs (list 50 { grantee: principal, resource-id: (string-ascii 64) })))
  (let (
    (batch-size (len grantee-resource-pairs))
    (batch-id (var-get total-consents))
    (initial-result { successful: u0, failed: u0 })
  )
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    (asserts! (<= batch-size MAX_BATCH_SIZE) ERR_BATCH_LIMIT_EXCEEDED)
    (asserts! (> batch-size u0) ERR_INVALID_TEMPLATE)

    (map-set batch-operations batch-id {
      initiator: tx-sender,
      operation-type: "BATCH_GRANT",
      total-operations: batch-size,
      successful-operations: u0,
      failed-operations: u0,
      started-at: stacks-block-height,
      completed-at: none,
      status: "IN_PROGRESS"
    })

    (let (
      (final-result (fold batch-grant-consent-helper grantee-resource-pairs initial-result))
    )
      (map-set batch-operations batch-id {
        initiator: tx-sender,
        operation-type: "BATCH_GRANT",
        total-operations: batch-size,
        successful-operations: (get successful final-result),
        failed-operations: (get failed final-result),
        started-at: stacks-block-height,
        completed-at: (some stacks-block-height),
        status: "COMPLETED"
      })

      (var-set total-consents (+ (var-get total-consents) (get successful final-result)))
      (ok final-result)
    )
  )
)

(define-private (batch-revoke-consent-helper
  (grantee-resource-pair { grantee: principal, resource-id: (string-ascii 64) })
  (previous-result { successful: uint, failed: uint }))
  (let (
    (consent-key { grantor: tx-sender, 
                  grantee: (get grantee grantee-resource-pair), 
                  resource-id: (get resource-id grantee-resource-pair) })
    (consent-data (map-get? consents consent-key))
  )
    (match consent-data
      consent-info
        (if (get is-active consent-info)
          (begin
            (map-set consents consent-key 
              (merge consent-info { is-active: false }))

            (map-set user-consent-count (get grantee grantee-resource-pair)
              (- (default-to u1 (map-get? user-consent-count (get grantee grantee-resource-pair))) u1))

            { successful: (+ (get successful previous-result) u1), 
              failed: (get failed previous-result) }
          )
          { successful: (get successful previous-result), 
            failed: (+ (get failed previous-result) u1) }
        )
      { successful: (get successful previous-result), 
        failed: (+ (get failed previous-result) u1) }
    )
  )
)

(define-public (batch-revoke-consents
  (grantee-resource-pairs (list 50 { grantee: principal, resource-id: (string-ascii 64) })))
  (let (
    (batch-size (len grantee-resource-pairs))
    (batch-id (+ (var-get total-consents) u1000000))
    (initial-result { successful: u0, failed: u0 })
  )
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    (asserts! (<= batch-size MAX_BATCH_SIZE) ERR_BATCH_LIMIT_EXCEEDED)
    (asserts! (> batch-size u0) ERR_INVALID_TEMPLATE)

    (map-set batch-operations batch-id {
      initiator: tx-sender,
      operation-type: "BATCH_REVOKE",
      total-operations: batch-size,
      successful-operations: u0,
      failed-operations: u0,
      started-at: stacks-block-height,
      completed-at: none,
      status: "IN_PROGRESS"
    })

    (let (
      (final-result (fold batch-revoke-consent-helper grantee-resource-pairs initial-result))
    )
      (map-set batch-operations batch-id {
        initiator: tx-sender,
        operation-type: "BATCH_REVOKE",
        total-operations: batch-size,
        successful-operations: (get successful final-result),
        failed-operations: (get failed final-result),
        started-at: stacks-block-height,
        completed-at: (some stacks-block-height),
        status: "COMPLETED"
      })

      (ok final-result)
    )
  )
)

(define-read-only (get-template-details (template-id (string-ascii 64)))
  (map-get? consent-templates template-id)
)

(define-read-only (get-template-usage-stats 
  (template-id (string-ascii 64)) 
  (user principal))
  (map-get? template-usage { template-id: template-id, user: user })
)

(define-read-only (get-batch-operation-status (batch-id uint))
  (map-get? batch-operations batch-id)
)

(define-read-only (get-total-templates)
  (var-get template-count)
)

(define-read-only (is-template-active (template-id (string-ascii 64)))
  (match (map-get? consent-templates template-id)
    template-data (get is-active template-data)
    false
  )
)