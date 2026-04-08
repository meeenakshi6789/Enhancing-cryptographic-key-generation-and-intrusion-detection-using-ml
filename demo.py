"""
Demonstration of the hybrid encryption workflow.

Shows the complete flow:
1. Sender prepares encrypted package
2. IDS evaluates for suspicious activity
3. Safe messages: Direct receiver decryption
4. Suspicious messages: TTP verification and audit
"""

from hybrid_encryption import generate_ecc_keypair, serialize_public_key
from ids_engine import IDSRuleEngine
from entities import Sender, Receiver, TTP
import json


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def print_package_summary(package: dict) -> None:
    """Print a summary of the encrypted package."""
    print("Package Structure:")
    print(f"  Sender ID: {package['sender_id']}")
    print(f"  Encrypted Payload:")
    print(f"    - Nonce: {package['enc_payload']['nonce'][:20]}...")
    print(f"    - Ciphertext: {package['enc_payload']['ciphertext'][:30]}...")
    print(f"  HMAC Tag: {package['hmac_b64'][:30]}...")
    print(f"  Wrapped Key:")
    print(f"    - Ephemeral Pub: {package['wrapped_key']['ephemeral_pub'][:30]}...")
    print(f"    - Nonce: {package['wrapped_key']['nonce'][:20]}...")
    print(f"    - Wrapped Key: {package['wrapped_key']['wrapped_key'][:30]}...")


def demo_safe_message():
    """Demo: Safe message flow (known sender, valid HMAC, matching IPs)."""
    print_section("DEMO 1: Safe Message Flow")
    
    # Setup
    sender = Sender("alice@example.com", "192.168.1.100", "192.168.1.200")
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    receiver = Receiver(receiver_priv, "192.168.1.200")
    
    # Sender prepares package
    plaintext = b"Hello, this is a safe message from Alice!"
    package = sender.prepare_package(plaintext, receiver_pub_bytes)
    
    print("1. SENDER: Prepares encrypted package")
    print_package_summary(package)
    print(f"  Sender IP: {package.get('sender_ip', 'N/A')}")
    print(f"  Receiver IP: {package.get('receiver_ip', 'N/A')}")
    
    # IDS evaluation
    print("\n2. IDS: Evaluates package")
    ids = IDSRuleEngine()
    ids.add_known_sender("alice@example.com")
    
    context = {
        "sender_id": package["sender_id"],
        "sender_ip": package.get("sender_ip"),
        "receiver_ip": package.get("receiver_ip"),
        "expected_sender_ip": "192.168.1.100",
        "expected_receiver_ip": "192.168.1.200",
        "ciphertext_b64": package["enc_payload"]["ciphertext"],
        "hmac_b64": package.get("hmac_b64")
    }
    
    is_suspicious, triggers = ids.evaluate(context)
    print(f"  IDS Decision: {'🚨 SUSPICIOUS' if is_suspicious else '✓ SAFE'}")
    if triggers:
        print(f"  Triggered Rules: {', '.join(triggers)}")
    else:
        print(f"  Triggered Rules: None")
    
    # Receiver decryption
    print("\n3. RECEIVER: Decrypts package")
    result = receiver.try_decrypt(package, "192.168.1.100")
    print(f"  Status: {result['status']}")
    if result['status'] == 'ok':
        print(f"  Plaintext: {result['plaintext'].decode()}")
    else:
        print(f"  Error: {result.get('error', 'Unknown error')}")
    
    print("\n✓ Safe message flow completed successfully!")


def demo_suspicious_message():
    """Demo: Suspicious message flow (unknown sender)."""
    print_section("DEMO 2: Suspicious Message Flow (Unknown Sender)")
    
    # Setup
    sender = Sender("unknown@attacker.com")  # Unknown sender
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    ttp = TTP(receiver_priv)
    receiver = Receiver(receiver_priv)
    
    # Sender prepares package
    plaintext = b"Suspicious message from unknown sender"
    package = sender.prepare_package(plaintext, receiver_pub_bytes)
    
    print("1. SENDER: Prepares encrypted package")
    print(f"  Sender ID: {package['sender_id']} (⚠️  UNKNOWN)")
    
    # IDS evaluation
    print("\n2. IDS: Evaluates package")
    ids = IDSRuleEngine()
    # Note: unknown@attacker.com is NOT in known_senders
    
    context = {
        "sender_id": package["sender_id"],
        "ciphertext_b64": package["enc_payload"]["ciphertext"],
        "hmac_b64": package.get("hmac_b64")
    }
    
    is_suspicious, triggers = ids.evaluate(context)
    print(f"  IDS Decision: {'🚨 SUSPICIOUS' if is_suspicious else '✓ SAFE'}")
    print(f"  Triggered Rules: {', '.join(triggers)}")
    
    # TTP verification
    if is_suspicious:
        print("\n3. TTP: Forwarding to Trusted Third Party for verification")
        ttp_result = ttp.decrypt_for_audit(package)
        print(f"  TTP Status: {ttp_result['status']}")
        if ttp_result['status'] == 'ok':
            print(f"  Plaintext (Audited): {ttp_result['plaintext'].decode()}")
            print(f"  ⚠️  ALERT: Suspicious message decrypted and logged")
        else:
            print(f"  Error: {ttp_result.get('error', 'Unknown error')}")
        
        # Show audit log
        print("\n  TTP Audit Log:")
        for entry in ttp.get_audit_log():
            print(f"    - Timestamp: {entry['timestamp']:.2f}")
            print(f"      Sender: {entry['sender']}")
            print(f"      Status: {entry['status']}")
            if 'payload_size' in entry:
                print(f"      Payload Size: {entry['payload_size']} bytes")
    
    print("\n✓ Suspicious message flow completed!")


def demo_integrity_failure():
    """Demo: Message with tampered ciphertext (integrity failure)."""
    print_section("DEMO 3: Integrity Failure (Tampered Ciphertext)")
    
    # Setup
    sender = Sender("bob@example.com")
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    receiver = Receiver(receiver_priv)
    
    # Sender prepares package
    plaintext = b"Original message from Bob"
    package = sender.prepare_package(plaintext, receiver_pub_bytes)
    
    print("1. SENDER: Prepares encrypted package")
    print(f"  Original Plaintext: {plaintext.decode()}")
    
    # Attacker tampers with ciphertext
    print("\n2. ATTACKER: Tampers with ciphertext")
    original_ct = package["enc_payload"]["ciphertext"]
    # Flip a bit in the ciphertext
    ct_bytes = bytearray(__import__("base64").b64decode(original_ct))
    ct_bytes[0] ^= 0x01  # Flip first bit
    tampered_ct = __import__("base64").b64encode(ct_bytes).decode()
    package["enc_payload"]["ciphertext"] = tampered_ct
    print(f"  ⚠️  Ciphertext modified (bit flipped)")
    
    # Receiver attempts decryption
    print("\n3. RECEIVER: Attempts to decrypt tampered package")
    result = receiver.try_decrypt(package)
    print(f"  Status: {result['status']}")
    if result['status'] == 'integrity_failed':
        print(f"  ✓ Integrity check FAILED - tampering detected!")
    else:
        print(f"  Error: {result.get('error', 'Unknown error')}")
    
    print("\n✓ Integrity failure detection completed!")


def demo_rate_limiting():
    """Demo: Rate limiting detection."""
    print_section("DEMO 4: Rate Limiting Detection")
    
    # Setup
    sender = Sender("spam@example.com")
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    
    # Create IDS with low rate limit for demo
    ids = IDSRuleEngine()
    ids.update_config("max_requests_per_minute", 3)
    ids.add_known_sender("spam@example.com")
    
    print("1. IDS Configuration:")
    print(f"  Max requests per minute: {ids.config['max_requests_per_minute']}")
    print(f"  Request window: {ids.config['request_window_seconds']} seconds")
    
    # Send multiple messages rapidly
    print("\n2. SENDER: Sends multiple messages rapidly")
    for i in range(5):
        plaintext = f"Message {i+1}".encode()
        package = sender.prepare_package(plaintext, receiver_pub_bytes)
        
        context = {
            "sender_id": package["sender_id"],
            "ciphertext_b64": package["enc_payload"]["ciphertext"],
            "hmac_b64": package.get("hmac_b64")
        }
        
        is_suspicious, triggers = ids.evaluate(context)
        status = "🚨 SUSPICIOUS" if is_suspicious else "✓ SAFE"
        print(f"  Message {i+1}: {status}", end="")
        if is_suspicious:
            print(f" (Triggers: {', '.join(triggers)})")
        else:
            print()
    
    print("\n✓ Rate limiting detection completed!")


def demo_multiple_senders():
    """Demo: Multiple senders with different trust levels."""
    print_section("DEMO 5: Multiple Senders with Different Trust Levels")
    
    # Setup
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    ids = IDSRuleEngine()
    
    # Define senders
    senders_config = [
        ("alice@example.com", True, "Trusted sender"),
        ("bob@example.com", True, "Trusted sender"),
        ("charlie@example.com", False, "Untrusted sender"),
        ("dave@example.com", False, "Untrusted sender"),
    ]
    
    print("1. IDS Configuration:")
    print(f"  Known senders: {', '.join([s[0] for s in senders_config if s[1]])}")
    for sender_id, trusted, desc in senders_config:
        if trusted:
            ids.add_known_sender(sender_id)
    
    # Send messages from each sender
    print("\n2. MESSAGES FROM DIFFERENT SENDERS:")
    for sender_id, trusted, desc in senders_config:
        sender = Sender(sender_id)
        plaintext = f"Message from {sender_id}".encode()
        package = sender.prepare_package(plaintext, receiver_pub_bytes)
        
        context = {
            "sender_id": package["sender_id"],
            "ciphertext_b64": package["enc_payload"]["ciphertext"],
            "hmac_b64": package.get("hmac_b64")
        }
        
        is_suspicious, triggers = ids.evaluate(context)
        status = "🚨 SUSPICIOUS" if is_suspicious else "✓ SAFE"
        trust_level = "✓ Trusted" if trusted else "⚠️  Untrusted"
        
        print(f"\n  {sender_id} ({trust_level})")
        print(f"    Status: {status}")
        if triggers:
            print(f"    Triggered Rules: {', '.join(triggers)}")
    
    print("\n✓ Multiple senders demo completed!")


def main():
    """Run all demonstrations."""
    print("\n" + "="*70)
    print("  HYBRID AES + ECC ENCRYPTION WITH RULE-BASED IDS AND TTP")
    print("="*70)
    
    try:
        demo_safe_message()
        demo_suspicious_message()
        demo_integrity_failure()
        demo_rate_limiting()
        demo_multiple_senders()
        
        print_section("ALL DEMOS COMPLETED SUCCESSFULLY")
        print("✓ All workflow demonstrations completed!")
        print("✓ Encryption, IDS, and TTP systems are functioning correctly.\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


def demo_ip_mismatch():
    """Demo: IP address mismatch detection."""
    print_section("DEMO 6: IP Address Mismatch Detection")
    
    # Setup - sender with wrong IP
    sender = Sender("alice@example.com", "192.168.1.100", "192.168.1.200")
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    receiver = Receiver(receiver_priv, "192.168.1.200")
    
    # Sender prepares package
    plaintext = b"Message from Alice with IP mismatch"
    package = sender.prepare_package(plaintext, receiver_pub_bytes)
    
    print("1. SENDER: Prepares encrypted package")
    print(f"  Sender ID: {package['sender_id']}")
    print(f"  Sender IP: {package.get('sender_ip', 'N/A')}")
    print(f"  Receiver IP: {package.get('receiver_ip', 'N/A')}")
    
    # IDS evaluation with wrong expected IP
    print("\n2. IDS: Evaluates package with IP mismatch")
    ids = IDSRuleEngine()
    ids.add_known_sender("alice@example.com")
    
    context = {
        "sender_id": package["sender_id"],
        "sender_ip": package.get("sender_ip"),
        "receiver_ip": package.get("receiver_ip"),
        "expected_sender_ip": "10.0.0.1",  # Different IP!
        "expected_receiver_ip": "192.168.1.200",
        "ciphertext_b64": package["enc_payload"]["ciphertext"],
        "hmac_b64": package.get("hmac_b64")
    }
    
    is_suspicious, triggers = ids.evaluate(context)
    print(f"  IDS Decision: {'🚨 SUSPICIOUS' if is_suspicious else '✓ SAFE'}")
    if triggers:
        print(f"  Triggered Rules: {', '.join(triggers)}")
    
    # Receiver decryption with wrong expected IP
    print("\n3. RECEIVER: Attempts decryption with IP validation")
    result = receiver.try_decrypt(package, "10.0.0.1")  # Wrong IP
    print(f"  Status: {result['status']}")
    if result['status'] == 'ip_mismatch':
        print(f"  🚨 IP Mismatch Detected: {result['error']}")
    elif result['status'] == 'ok':
        print(f"  Plaintext: {result['plaintext'].decode()}")
    else:
        print(f"  Error: {result.get('error', 'Unknown error')}")
    
    print("\n✓ IP mismatch detection completed!")


def demo_receiver_ip_mismatch():
    """Demo: Receiver IP address mismatch detection."""
    print_section("DEMO 7: Receiver IP Address Mismatch Detection")
    
    # Setup - sender targeting wrong receiver IP
    sender = Sender("alice@example.com", "192.168.1.100", "10.0.0.50")  # Wrong receiver IP
    receiver_priv, receiver_pub = generate_ecc_keypair()
    receiver_pub_bytes = serialize_public_key(receiver_pub)
    receiver = Receiver(receiver_priv, "192.168.1.200")  # Actual receiver IP
    
    # Sender prepares package
    plaintext = b"Message targeting wrong receiver IP"
    package = sender.prepare_package(plaintext, receiver_pub_bytes)
    
    print("1. SENDER: Prepares encrypted package")
    print(f"  Sender ID: {package['sender_id']}")
    print(f"  Sender IP: {package.get('sender_ip', 'N/A')}")
    print(f"  Target Receiver IP: {package.get('receiver_ip', 'N/A')}")
    print(f"  Actual Receiver IP: {receiver.receiver_ip}")
    
    # IDS evaluation
    print("\n2. IDS: Evaluates package with receiver IP mismatch")
    ids = IDSRuleEngine()
    ids.add_known_sender("alice@example.com")
    
    context = {
        "sender_id": package["sender_id"],
        "sender_ip": package.get("sender_ip"),
        "receiver_ip": package.get("receiver_ip"),
        "expected_sender_ip": "192.168.1.100",
        "expected_receiver_ip": "192.168.1.200",  # Different from target
        "ciphertext_b64": package["enc_payload"]["ciphertext"],
        "hmac_b64": package.get("hmac_b64")
    }
    
    is_suspicious, triggers = ids.evaluate(context)
    print(f"  IDS Decision: {'🚨 SUSPICIOUS' if is_suspicious else '✓ SAFE'}")
    if triggers:
        print(f"  Triggered Rules: {', '.join(triggers)}")
    
    print("\n✓ Receiver IP mismatch detection completed!")


def main():
    """Run all demonstrations."""
    try:
        demo_safe_message()
        demo_suspicious_message()
        demo_integrity_failure()
        demo_rate_limiting()
        demo_multiple_senders()
        demo_ip_mismatch()
        demo_receiver_ip_mismatch()
        
        print_section("ALL DEMOS COMPLETED SUCCESSFULLY")
        print("✓ All workflow demonstrations completed!")
        print("✓ Encryption, IDS, and TTP systems are functioning correctly.")
        print("✓ IP-based intrusion detection is working correctly.\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
