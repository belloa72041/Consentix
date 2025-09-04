;; Consent Expiry Notification System
;; Manages notification thresholds and tracks approaching consent expirations

(define-constant ERR_UNAUTHORIZED (err u200))
(define-constant ERR_NOT_FOUND (err u201))
(define-constant ERR_INVALID_THRESHOLD (err u202))
(define-constant ERR_NOTIFICATION_EXISTS (err u203))
(define-constant ERR_INVALID_BLOCKS (err u204))
(define-constant ERR_SUBSCRIPTION_LIMIT (err u205))

(define-constant MAX_SUBSCRIPTIONS_PER_USER u100)
(define-constant DEFAULT_NOTIFICATION_THRESHOLD u144) ;; ~1 day in blocks

;; Track notification settings for users
(define-map notification-settings
  principal
  {
    default-threshold: uint,
    notifications-enabled: bool,
    total-subscriptions: uint,
    created-at: uint
  }
)

;; Track specific consent notification subscriptions
(define-map expiry-subscriptions
  { user: principal, grantor: principal, grantee: principal, resource-id: (string-ascii 64) }
  {
    threshold-blocks: uint,
    notification-sent: bool,
    created-at: uint,
    last-checked: uint
  }
)

;; Store notification history
(define-map notification-history
  { user: principal, notification-id: uint }
  {
    consent-key: { grantor: principal, grantee: principal, resource-id: (string-ascii 64) },
    notification-type: (string-ascii 32),
    sent-at: uint,
    expires-at: uint,
    blocks-remaining: uint
  }
)

;; Track pending notifications
(define-map pending-notifications
  uint
  {
    user: principal,
    consent-key: { grantor: principal, grantee: principal, resource-id: (string-ascii 64) },
    expires-at: uint,
    threshold-blocks: uint,
    created-at: uint
  }
)

;; Global counters
(define-data-var notification-counter uint u0)
(define-data-var pending-notification-counter uint u0)

;; Initialize or update user notification settings
(define-public (set-notification-preferences 
  (threshold-blocks uint)
  (enabled bool))
  (begin
    (asserts! (>= threshold-blocks u10) ERR_INVALID_THRESHOLD)
    (asserts! (<= threshold-blocks u14400) ERR_INVALID_THRESHOLD) ;; Max ~100 days
    
    (let (
      (existing-settings (map-get? notification-settings tx-sender))
    )
      (match existing-settings
        settings
          (map-set notification-settings tx-sender
            (merge settings {
              default-threshold: threshold-blocks,
              notifications-enabled: enabled
            }))
        (map-set notification-settings tx-sender {
          default-threshold: threshold-blocks,
          notifications-enabled: enabled,
          total-subscriptions: u0,
          created-at: stacks-block-height
        })
      )
    )
    (ok true)
  )
)

;; Subscribe to notifications for specific consent
(define-public (subscribe-to-consent-expiry
  (grantor principal)
  (grantee principal)  
  (resource-id (string-ascii 64))
  (custom-threshold (optional uint)))
  (let (
    (subscription-key { user: tx-sender, grantor: grantor, grantee: grantee, resource-id: resource-id })
    (user-settings (default-to 
      { default-threshold: DEFAULT_NOTIFICATION_THRESHOLD, notifications-enabled: true, total-subscriptions: u0, created-at: stacks-block-height }
      (map-get? notification-settings tx-sender)))
    (threshold (default-to (get default-threshold user-settings) custom-threshold))
  )
    (asserts! (get notifications-enabled user-settings) ERR_UNAUTHORIZED)
    (asserts! (< (get total-subscriptions user-settings) MAX_SUBSCRIPTIONS_PER_USER) ERR_SUBSCRIPTION_LIMIT)
    (asserts! (is-none (map-get? expiry-subscriptions subscription-key)) ERR_NOTIFICATION_EXISTS)
    (asserts! (>= threshold u10) ERR_INVALID_THRESHOLD)
    
    ;; Create subscription
    (map-set expiry-subscriptions subscription-key {
      threshold-blocks: threshold,
      notification-sent: false,
      created-at: stacks-block-height,
      last-checked: stacks-block-height
    })
    
    ;; Update user subscription count
    (map-set notification-settings tx-sender
      (merge user-settings {
        total-subscriptions: (+ (get total-subscriptions user-settings) u1)
      }))
    
    (ok true)
  )
)

;; Remove subscription for consent expiry notifications
(define-public (unsubscribe-from-consent-expiry
  (grantor principal)
  (grantee principal)
  (resource-id (string-ascii 64)))
  (let (
    (subscription-key { user: tx-sender, grantor: grantor, grantee: grantee, resource-id: resource-id })
    (subscription (unwrap! (map-get? expiry-subscriptions subscription-key) ERR_NOT_FOUND))
    (user-settings (unwrap! (map-get? notification-settings tx-sender) ERR_NOT_FOUND))
  )
    ;; Remove subscription
    (map-delete expiry-subscriptions subscription-key)
    
    ;; Update user subscription count
    (map-set notification-settings tx-sender
      (merge user-settings {
        total-subscriptions: (- (get total-subscriptions user-settings) u1)
      }))
    
    (ok true)
  )
)

;; Check and process expiry notifications (callable by anyone to maintain the system)
(define-public (check-consent-expiry
  (grantor principal)
  (grantee principal)
  (resource-id (string-ascii 64))
  (consent-expires-at uint))
  (let (
    (current-block stacks-block-height)
    (blocks-remaining (if (> consent-expires-at current-block) 
                        (- consent-expires-at current-block) 
                        u0))
  )
    ;; Find all subscriptions for this consent and trigger notifications
    (process-consent-notifications grantor grantee resource-id consent-expires-at blocks-remaining)
  )
)

;; Internal function to process notifications for a specific consent
(define-private (process-consent-notifications
  (grantor principal)
  (grantee principal)
  (resource-id (string-ascii 64))
  (expires-at uint)
  (blocks-remaining uint))
  (let (
    (current-block stacks-block-height)
  )
    ;; This would typically iterate through subscriptions, but for simplicity
    ;; we'll create a direct notification system
    (create-pending-notification grantor grantee resource-id expires-at blocks-remaining)
  )
)

;; Create a pending notification
(define-private (create-pending-notification
  (grantor principal)
  (grantee principal)
  (resource-id (string-ascii 64))
  (expires-at uint)
  (blocks-remaining uint))
  (let (
    (notification-id (+ (var-get pending-notification-counter) u1))
    (consent-key { grantor: grantor, grantee: grantee, resource-id: resource-id })
  )
    (var-set pending-notification-counter notification-id)
    
    (map-set pending-notifications notification-id {
      user: grantor, ;; Notify the grantor
      consent-key: consent-key,
      expires-at: expires-at,
      threshold-blocks: blocks-remaining,
      created-at: stacks-block-height
    })
    
    (ok notification-id)
  )
)

;; Mark notification as sent and move to history
(define-public (mark-notification-sent (notification-id uint))
  (let (
    (notification (unwrap! (map-get? pending-notifications notification-id) ERR_NOT_FOUND))
    (user (get user notification))
    (history-id (+ (var-get notification-counter) u1))
  )
    ;; Only the user can mark their own notifications as sent
    (asserts! (is-eq tx-sender user) ERR_UNAUTHORIZED)
    
    ;; Move to history
    (var-set notification-counter history-id)
    (map-set notification-history { user: user, notification-id: history-id } {
      consent-key: (get consent-key notification),
      notification-type: "EXPIRY_REMINDER",
      sent-at: stacks-block-height,
      expires-at: (get expires-at notification),
      blocks-remaining: (get threshold-blocks notification)
    })
    
    ;; Remove from pending
    (map-delete pending-notifications notification-id)
    
    (ok true)
  )
)

;; Get user notification settings
(define-read-only (get-notification-settings (user principal))
  (map-get? notification-settings user)
)

;; Get subscription details
(define-read-only (get-subscription-details
  (user principal)
  (grantor principal) 
  (grantee principal)
  (resource-id (string-ascii 64)))
  (map-get? expiry-subscriptions { user: user, grantor: grantor, grantee: grantee, resource-id: resource-id })
)

;; Get pending notifications for a user
(define-read-only (get-pending-notification (notification-id uint))
  (map-get? pending-notifications notification-id)
)

;; Get notification history for user
(define-read-only (get-notification-history 
  (user principal)
  (notification-id uint))
  (map-get? notification-history { user: user, notification-id: notification-id })
)

;; Check how many blocks until consent expires
(define-read-only (blocks-until-expiry (expires-at uint))
  (if (> expires-at stacks-block-height)
    (- expires-at stacks-block-height)
    u0)
)

;; Get notification statistics for user
(define-read-only (get-user-notification-stats (user principal))
  (match (map-get? notification-settings user)
    settings {
      total-subscriptions: (get total-subscriptions settings),
      notifications-enabled: (get notifications-enabled settings),
      default-threshold: (get default-threshold settings),
      account-age-blocks: (- stacks-block-height (get created-at settings))
    }
    { total-subscriptions: u0, notifications-enabled: false, default-threshold: u0, account-age-blocks: u0 }
  )
)

;; Get system notification stats
(define-read-only (get-system-notification-stats)
  {
    total-notifications-sent: (var-get notification-counter),
    pending-notifications: (var-get pending-notification-counter),
    default-threshold-blocks: DEFAULT_NOTIFICATION_THRESHOLD,
    max-subscriptions-per-user: MAX_SUBSCRIPTIONS_PER_USER
  }
)
