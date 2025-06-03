# 🔐 Consentix - Consent Management Smart Contract

> 🚀 A decentralized consent management system built on Stacks blockchain using Clarity smart contracts

## 📋 Overview

Consentix enables users to grant, manage, and revoke access permissions to their digital assets and data in a transparent, secure, and decentralized manner. Perfect for applications requiring fine-grained access control and consent management.

## ✨ Features

- 🎯 **Grant Consent**: Give specific permissions to other users for your resources
- ⏰ **Time-based Expiry**: Set automatic expiration for consent grants  
- 🔄 **Revoke Access**: Instantly revoke previously granted permissions
- 📈 **Extend Duration**: Extend consent duration for active grants
- 🛡️ **Permission Validation**: Check if users have required permissions
- 📊 **Resource Management**: Register and manage resource permission requirements
- ⏸️ **Emergency Controls**: Contract pause/unpause functionality for admins

## 🏗️ Core Functions

### Public Functions

#### `grant-consent`
```clarity
(grant-consent grantee resource-id duration permissions metadata)
```
Grant access permissions to another user for a specific resource.

#### `revoke-consent`
```clarity
(revoke-consent grantee resource-id)
```
Revoke previously granted consent.

#### `extend-consent`
```clarity
(extend-consent grantee resource-id additional-duration)
```
Extend the duration of an existing consent.

#### `register-resource`
```clarity
(register-resource resource-id required-permissions is-public)
```
Register a new resource with permission requirements.

### Read-Only Functions

#### `check-consent`
```clarity
(check-consent grantor grantee resource-id)
```
Verify if consent is valid and active.

#### `has-permission`
```clarity
(has-permission grantor grantee resource-id required-permission)
```
Check if user has specific permission for a resource.

#### `get-consent-details`
```clarity
(get-consent-details grantor grantee resource-id)
```
Get complete consent information.

## 🚀 Quick Start

### Prerequisites
- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Stacks wallet for testing

### Installation

```bash
git clone <your-repo>
cd consentix
clarinet check
```

### Testing

```bash
clarinet test
```

### Deployment

```bash
clarinet deploy --testnet
```

## 💡 Usage Examples

### Grant File Access
```clarity
;; Grant read access to user for 1000 blocks
(contract-call? .consentix grant-consent 
  'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 
  "user-documents" 
  u1000 
  (list "read") 
  "Access to personal documents")
```

### Check Permission
```clarity
;; Verify if user can read the resource
(contract-call? .consentix has-permission 
  'SP1HTBVD3JG9C05J7HBJTHGR0GGW7KX975CN0QKK1
  'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7
  "user-documents" 
  "read")
```

### Revoke Access
```clarity
;; Remove previously granted access
(contract-call? .consentix revoke-consent 
  'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 
  "user-documents")
```

## 🔧 Error Codes

| Code | Description |
|------|-------------|
| `u100` | Unauthorized access |
| `u101` | Consent not found |
| `u102` | Consent expired |
| `u103` | Consent already revoked |
| `u104` | Invalid duration |
| `u105` | Resource already exists |
| `u106` | Invalid principal |

## 🛠️ Development

### Project Structure
```
├── contracts/
│   └── Consentix.clar
├── tests/
├── settings/
└── Clarinet.toml
```

### Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Support

- 📧 Create an issue for bug reports
- 💬 Join our community discussions
- 📖 Check the documentation

---


