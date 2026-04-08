# Hybrid Encryption Workflow Documentation

## Overview

This document describes the complete workflow of the hybrid AES + ECC encryption system with rule-based IDS and TTP verification.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         SENDER                                  │
│  - Generates AES session key                                    │
│  - Encrypts plaintext with AES-GCM                              │
│  - Computes HMAC for integrity                                  │
│  - Wraps AES key with receiver's ECC public key                 │
│  - Sends encrypted package                                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │   ENCRYPTED PACKAGE            │
        │  - sender_id                   │
        │  - enc_payload (nonce + ct)    │
        │  - hmac_b64                    │
        │  - wrapped_key                 │
        └────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    IDS RULE ENGINE                              │
│  Evaluates multiple security rules:                             │
│  ✓ rule_unknown_sender                                          │
│  ✓ rule_missing_integrity                                       │
│  ✓ rule_large_payload                                           │
│  ✓ rule_high_cipher_entropy                                     │
│  ✓ rule_rapid_requests                                          │
│  ✓ rule_invalid_base64                                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                    ┌────┴────┐
                    │          │
              SAFE  │          │  SUSPICIOUS
                    ▼          ▼
        ┌──────────────────┐  ┌──────────────────┐
        │    RECEIVER      │  │       TTP        │
        │  - Unwrap AES    │  │  - Unwrap AES    │
        │  - Verify HMAC   │  │  - Verify HMAC   │
        │  - Decrypt       │  │  - Decrypt       │
        │  - Accept        │  │  - Audit Log     │
        │                  │  │  - Alert/Report  │
        └──────────────────┘  └──────────────────┘
                    │                  │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │  PLAINTEXT       │
                    │  ACCEPTED/ALERT  │
                    └──────────────────┘
```

## Detailed Workflow Steps

### Phase 1: Message Preparation (Sender)

#### Step 1.1: Generate AES Session Key
```python
aes_key = generate_aes_key()  # 256-bit random key
```
- Creates a fresh, random AES-256 key for this message
- Key is never transmitted in plaintext
- Each message gets a unique session key

#### Step 1.2: Encrypt Payload with AES-GCM
```python
enc = aes_encrypt(aes_key, plaintext)
# Returns: {"nonce": b64(nonce), "ciphertext": b64(ct)}
```
- Uses AES-GCM (Galois/Counter Mode)
- Provides both confidentiality and authentication
- Nonce is randomly generated (96 bits)
- Ciphertext includes authentication tag

#### Step 1.3: Compute HMAC for Integrity
```python
hmac_tag = compute_hmac(aes_key, ciphertext)
```
- Additional integrity verification layer
- HMAC-SHA256 using the AES session key
- Protects against tampering with ciphertext
- Provides non-repudiation evidence

#### Step 1.4: Wrap AES Key with ECC
```python
wrapped = wrap_aes_key_with_ecc(receiver_pub_bytes, aes_key)
# Returns: {
#   "ephemeral_pub": b64(ephemeral_public_key),
#   "nonce": b64(nonce),
#   "wrapped_key": b64(encrypted_aes_key)
# }
```

**Key Wrapping Process:**
1. Generate ephemeral ECC keypair (SECP384R1)
2. Perform ECDH with receiver's public key
3. Derive symmetric wrapping key via HKDF-SHA256
4. Encrypt AES key with AES-GCM using derived key
5. Include ephemeral public key for receiver to perform ECDH

**Why this approach?**
- Ephemeral keys provide forward secrecy
- ECDH provides key agreement without pre-shared secrets
- HKDF expands shared secret into usable key material
- AES-GCM provides authenticated encryption

#### Step 1.5: Assemble Package
```python
package = {
    "sender_id": "alice@example.com",
    "enc_payload": {
        "nonce": b64(nonce),
        "ciphertext": b64(ct)
    },
    "hmac_b64": hmac_tag,
    "wrapped_key": {
        "ephemeral_pub": b64(ephemeral_pub),
        "nonce": b64(nonce),
        "wrapped_key": b64(wrapped_aes_key)
    }
}
```

---

### Phase 2: IDS Evaluation

#### Step 2.1: Build Context
```python
context = {
    "sender_id": package["sender_id"],
    "ciphertext_b64": package["enc_payload"]["ciphertext"],
    "hmac_b64": package.get("hmac_b64")
}
```

#### Step 2.2: Evaluate Rules

**Rule 1: Unknown Sender**
```python
def rule_unknown_sender(context):
    return context.get("sender_id") not in self.known_senders
```
- Flags messages from senders not in whitelist
- Prevents communication with untrusted parties
- Can be updated dynamically

**Rule 2: Missing Integrity**
```python
def rule_missing_integrity(context):
    return not bool(context.get("hmac_b64"))
```
- Flags messages without HMAC tag
- Ensures integrity verification is available
- Prevents downgrade attacks

**Rule 3: Large Payload**
```python
def rule_large_payload(context):
    ct_len = len(ub64(context.get("ciphertext_b64", "")))
    return ct_len > 10 * 1024  # 10 KB threshold
```
- Detects suspiciously large messages
- Prevents resource exhaustion
- Threshold is configurable

**Rule 4: High Cipher Entropy**
```python
def rule_high_cipher_entropy(context):
    ct = ub64(context.get("ciphertext_b64", ""))
    uniq = len(set(ct))
    return uniq / len(ct) > 0.75
```
- Detects anomalies in encrypted data
- High entropy is normal for encrypted data
- Can indicate compression or encoding issues

**Rule 5: Rapid Requests**
```python
def rule_rapid_requests(context):
    # Count requests from sender in time window
    # Flag if exceeds threshold (e.g., >10 per minute)
    return request_count > max_requests
```
- Implements rate limiting
- Prevents flooding attacks
- Per-sender tracking with sliding window

**Rule 6: Invalid Base64**
```python
def rule_invalid_base64(context):
    try:
        ub64(context.get("ciphertext_b64", ""))
        ub64(context.get("hmac_b64", ""))
        return False
    except:
        return True
```
- Validates encoding format
- Detects malformed messages
- Prevents parsing errors

#### Step 2.3: Aggregate Results
```python
is_suspicious, triggers = ids.evaluate(context)
# is_suspicious: True if ANY rule triggers
# triggers: List of rule names that triggered
```

---

### Phase 3A: Safe Message Flow (Direct Receiver)

**Condition:** `is_suspicious == False`

#### Step 3A.1: Receiver Unwraps AES Key
```python
aes_key = unwrap_aes_key_with_ecc(
    receiver_priv,
    wrapped["ephemeral_pub"],
    wrapped["nonce"],
    wrapped["wrapped_key"]
)
```

**Unwrapping Process:**
1. Deserialize ephemeral public key
2. Perform ECDH with receiver's private key
3. Derive symmetric wrapping key via HKDF-SHA256
4. Decrypt AES key with AES-GCM

**Security Note:** Only receiver with private key can unwrap

#### Step 3A.2: Verify HMAC Integrity
```python
ok = verify_hmac(aes_key, ciphertext, hmac_tag)
if not ok:
    return {"status": "integrity_failed"}
```

#### Step 3A.3: Decrypt Payload
```python
plaintext = aes_decrypt(aes_key, nonce, ciphertext)
```

#### Step 3A.4: Accept Plaintext
```python
return {"status": "ok", "plaintext": plaintext}
```

---

### Phase 3B: Suspicious Message Flow (TTP Verification)

**Condition:** `is_suspicious == True`

#### Step 3B.1: Forward to TTP
```python
print("Forwarding to TTP for verification...")
```

#### Step 3B.2: TTP Unwraps and Decrypts
```python
result = ttp.decrypt_for_audit(package)
```

**TTP Process:**
1. Unwrap AES key (same as receiver)
2. Verify HMAC integrity
3. Decrypt payload
4. Log audit entry (without storing plaintext)
5. Return result

#### Step 3B.3: Audit Logging
```python
audit_entry = {
    "timestamp": time.time(),
    "sender": package.get("sender_id"),
    "status": "decrypted",
    "payload_size": len(plaintext)
}
ttp.audit_log.append(audit_entry)
```

**Logged Information:**
- Timestamp of decryption
- Sender identity
- Status (decrypted/failed)
- Payload size (NOT plaintext content)

#### Step 3B.4: Alert/Report
```python
print("⚠️  ALERT: Suspicious message decrypted and logged")
# System can:
# - Send alert to security team
# - Block sender
# - Quarantine message
# - Trigger investigation
```

---

## Security Properties

### Confidentiality
- **AES-GCM:** Provides semantic security
- **ECC Wrapping:** Only receiver can unwrap AES key
- **Ephemeral Keys:** Each message uses fresh key material
- **Session Keys:** Unique AES key per message

### Integrity
- **AES-GCM Tag:** Authenticates ciphertext
- **HMAC-SHA256:** Additional integrity layer
- **Dual Verification:** Both must pass for acceptance

### Authentication
- **Sender ID:** Identifies message origin
- **IDS Rules:** Validates sender trust level
- **HMAC:** Provides evidence of sender knowledge

### Non-Repudiation
- **HMAC Tag:** Proves sender computed it
- **Audit Log:** Records all suspicious messages
- **TTP Verification:** Independent verification

### Availability
- **Rate Limiting:** Prevents flooding
- **Payload Size Limits:** Prevents resource exhaustion
- **Graceful Degradation:** TTP handles suspicious messages

---

## Threat Model

### Threats Addressed

1. **Eavesdropping**
   - Mitigated by: AES-GCM encryption
   - Only receiver with private key can decrypt

2. **Message Tampering**
   - Mitigated by: HMAC + AES-GCM authentication
   - Tampering detected during decryption

3. **Replay Attacks**
   - Mitigated by: Unique nonces per message
   - Each message has fresh ephemeral key

4. **Unauthorized Senders**
   - Mitigated by: IDS rule_unknown_sender
   - Only trusted senders bypass IDS

5. **Flooding/DoS**
   - Mitigated by: Rate limiting + payload size limits
   - Prevents resource exhaustion

6. **Key Compromise**
   - Mitigated by: Ephemeral keys
   - Compromise of one key doesn't affect others
   - Forward secrecy for past messages

### Threats NOT Addressed

1. **TTP Backdoor**
   - TTP has access to receiver's private key
   - Centralized point of failure
   - Mitigation: Use threshold cryptography

2. **Side-Channel Attacks**
   - Timing attacks on decryption
   - Power analysis attacks
   - Mitigation: Use constant-time implementations

3. **Quantum Attacks**
   - ECC vulnerable to quantum computers
   - Mitigation: Use post-quantum cryptography

4. **Compromised Receiver**
   - If receiver's private key is stolen
   - All past messages can be decrypted
   - Mitigation: Key rotation + secure key storage

---

## Configuration

### IDS Thresholds

```python
ids.config = {
    "max_payload_size": 10 * 1024,           # 10 KB
    "entropy_threshold": 0.75,                # 75% unique bytes
    "max_requests_per_minute": 10,            # Rate limit
    "request_window_seconds": 60,             # Time window
}
```

### Update Configuration

```python
ids.update_config("max_payload_size", 5 * 1024)  # 5 KB
```

### Manage Known Senders

```python
ids.add_known_sender("alice@example.com")
ids.remove_known_sender("bob@example.com")
```

---

## Usage Examples

### Example 1: Safe Message Flow

```python
from hybrid_encryption import generate_ecc_keypair, serialize_public_key
from ids_engine import IDSRuleEngine
from entities import Sender, Receiver

# Setup
sender = Sender("alice@example.com")
receiver_priv, receiver_pub = generate_ecc_keypair()
receiver_pub_bytes = serialize_public_key(receiver_pub)

# Send message
plaintext = b"Hello, World!"
package = sender.prepare_package(plaintext, receiver_pub_bytes)

# IDS evaluation
ids = IDSRuleEngine()
ids.add_known_sender("alice@example.com")
context = {
    "sender_id": package["sender_id"],
    "ciphertext_b64": package["enc_payload"]["ciphertext"],
    "hmac_b64": package.get("hmac_b64")
}
is_suspicious, triggers = ids.evaluate(context)

# Receive message
if not is_suspicious:
    receiver = Receiver(receiver_priv)
    result = receiver.try_decrypt(package)
    print(result["plaintext"])  # b"Hello, World!"
```

### Example 2: Suspicious Message with TTP

```python
from entities import TTP

# Setup (same as above, but sender is unknown)
sender = Sender("unknown@attacker.com")
# ... prepare package ...

# IDS flags as suspicious
is_suspicious, triggers = ids.evaluate(context)  # True

if is_suspicious:
    ttp = TTP(receiver_priv)
    result = ttp.decrypt_for_audit(package)
    
    # Check audit log
    audit_log = ttp.get_audit_log()
    print(f"Decrypted {len(audit_log)} suspicious messages")
```

### Example 3: Integrity Failure Detection

```python
import base64

# Prepare message
plaintext = b"Original message"
package = sender.prepare_package(plaintext, receiver_pub_bytes)

# Attacker tampers with ciphertext
ct_bytes = bytearray(base64.b64decode(package["enc_payload"]["ciphertext"]))
ct_bytes[0] ^= 0x01  # Flip a bit
package["enc_payload"]["ciphertext"] = base64.b64encode(ct_bytes).decode()

# Receiver detects tampering
receiver = Receiver(receiver_priv)
result = receiver.try_decrypt(package)
print(result["status"])  # "integrity_failed"
```

---

## Performance Considerations

### Computational Complexity

| Operation | Time | Notes |
|-----------|------|-------|
| AES-256 Encryption | ~1-5 µs/KB | Hardware accelerated |
| AES-256 Decryption | ~1-5 µs/KB | Hardware accelerated |
| ECDH (SECP384R1) | ~1-5 ms | Per message |
| HKDF-SHA256 | ~0.1 ms | Per message |
| HMAC-SHA256 | ~0.1 µs/byte | Per message |
| IDS Evaluation | ~0.1-1 ms | Depends on rules |

### Memory Usage

| Component | Size |
|-----------|------|
| AES-256 Key | 32 bytes |
| ECC Private Key (SECP384R1) | 48 bytes |
| ECC Public Key (SECP384R1) | 97 bytes |
| ECDH Shared Secret | 48 bytes |
| HMAC-SHA256 Tag | 32 bytes |
| Nonce (96-bit) | 12 bytes |

---

## Deployment Recommendations

### Production Checklist

- [ ] Use Hardware Security Module (HSM) for key storage
- [ ] Implement threshold cryptography for TTP
- [ ] Add comprehensive logging (without sensitive data)
- [ ] Monitor IDS rule triggers
- [ ] Regular security audits
- [ ] Key rotation policies
- [ ] Incident response procedures
- [ ] Backup and recovery procedures
- [ ] Network segmentation
- [ ] Access control lists

### Security Hardening

1. **Key Management**
   - Use HSM or key management service
   - Implement key rotation
   - Secure key backup and recovery

2. **TTP Security**
   - Use threshold cryptography
   - Separate TTP from receiver
   - Audit all TTP operations
   - Implement access controls

3. **IDS Tuning**
   - Monitor false positives
   - Adjust thresholds based on traffic
   - Add custom rules for your environment
   - Integrate with SIEM

4. **Logging & Monitoring**
   - Log all IDS triggers
   - Log all TTP operations
   - Monitor for anomalies
   - Alert on suspicious patterns

---

## References

- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- SEC 2: Recommended Elliptic Curve Domain Parameters
- NIST SP 800-56A: Recommendation for Pair-Wise Key Establishment Schemes

