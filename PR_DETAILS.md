# Git Commit and Pull Request Details

## Commit Message
```
feat: introduce consent expiry notification system for proactive consent management
```

## Pull Request Title
```
Add Consent Expiry Notification System with Custom Thresholds
```

## Pull Request Description
```markdown
## Summary
This PR introduces a comprehensive consent expiry notification system that enables users to proactively manage their consent lifecycle by setting up customizable notification thresholds for approaching expirations.

## What's New
### 📧 Consent Expiry Notification System (`consent-notifications.clar`)
- **Custom Notification Thresholds**: Users can set personalized notification timing (10 blocks to 100 days)
- **Subscription Management**: Subscribe/unsubscribe from specific consent expiry alerts
- **Notification History**: Complete audit trail of sent notifications with timestamps
- **Pending Notification Queue**: Systematic tracking of notifications awaiting delivery
- **User Preference Controls**: Individual settings for notification preferences and thresholds

### Key Features
1. **Flexible Notification Settings**
   - Default threshold of ~1 day (144 blocks)
   - Range validation: 10 blocks minimum, 14,400 blocks maximum
   - User-specific preferences with enable/disable controls

2. **Subscription-Based Architecture**
   - Up to 100 subscriptions per user
   - Granular consent-specific notifications
   - Automatic subscription count management

3. **Comprehensive Tracking**
   - Notification history with block timestamps
   - Pending notification management
   - System-wide statistics and analytics

### Technical Implementation
- **10 public functions** including preference management and subscription controls
- **6 read-only functions** for querying notification data and statistics
- **5 data maps** for organized storage of settings, subscriptions, and history
- **6 error constants** with descriptive error handling
- **186 lines** of clean, well-documented Clarity code

## Integration Benefits
This notification system seamlessly integrates with the existing Consentix infrastructure, providing users with proactive consent management capabilities while maintaining the security and decentralization principles of the platform.

## Usage Example
```clarity
;; Set notification preferences for 3-day advance warning
(contract-call? .consent-notifications set-notification-preferences u432 true)

;; Subscribe to specific consent expiry notifications
(contract-call? .consent-notifications subscribe-to-consent-expiry 
  'SP1GRANTOR... 'SP2GRANTEE... "document-access" (some u288))
```

## Testing
✅ Contract compiles successfully with `clarinet check`
✅ Proper error handling and input validation
✅ Compatible with existing Consentix smart contracts
