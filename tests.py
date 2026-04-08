"""
Unit tests for the hybrid encryption system.

Tests cover:
- Encryption/decryption correctness
- Key wrapping/unwrapping
- HMAC integrity verification
- IDS rule engine
- Entity workflows
"""

import unittest
from hybrid_encryption import (
    generate_ecc_keypair,
    serialize_public_key,
    deserialize_public_key,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    wrap_aes_key_with_ecc,
    unwrap_aes_key_with_ecc,
    compute_hmac,
    verify_hmac,
    b64,
    ub64
)
from ids_engine import IDSRuleEngine
from entities import Sender, Receiver, TTP


class TestHybridEncryption(unittest.TestCase):
    """Test hybrid encryption functions."""

    def test_ecc_keypair_generation(self):
        """Test ECC keypair generation."""
        priv, pub = generate_ecc_keypair()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_public_key_serialization(self):
        """Test ECC public key serialization and deserialization."""
        priv, pub = generate_ecc_keypair()
        pub_bytes = serialize_public_key(pub)
        
        # Should be able to deserialize
        pub_restored = deserialize_public_key(pub_bytes)
        self.assertIsNotNone(pub_restored)

    def test_aes_key_generation(self):
        """Test AES key generation."""
        key = generate_aes_key()
        self.assertEqual(len(key), 32)  # 256-bit key

    def test_aes_encrypt_decrypt(self):
        """Test AES-GCM encryption and decryption."""
        key = generate_aes_key()
        plaintext = b"Test message"
        
        # Encrypt
        encrypted = aes_encrypt(key, plaintext)
        self.assertIn("nonce", encrypted)
        self.assertIn("ciphertext", encrypted)
        
        # Decrypt
        decrypted = aes_decrypt(key, encrypted["nonce"], encrypted["ciphertext"])
        self.assertEqual(decrypted, plaintext)

    def test_aes_decrypt_with_wrong_key(self):
        """Test that decryption fails with wrong key."""
        key1 = generate_aes_key()
        key2 = generate_aes_key()
        plaintext = b"Test message"
        
        encrypted = aes_encrypt(key1, plaintext)
        
        # Should fail with wrong key
        with self.assertRaises(Exception):
            aes_decrypt(key2, encrypted["nonce"], encrypted["ciphertext"])

    def test_key_wrapping(self):
        """Test AES key wrapping with ECC."""
        receiver_priv, receiver_pub = generate_ecc_keypair()
        receiver_pub_bytes = serialize_public_key(receiver_pub)
        
        aes_key = generate_aes_key()
        
        # Wrap key
        wrapped = wrap_aes_key_with_ecc(receiver_pub_bytes, aes_key)
        self.assertIn("ephemeral_pub", wrapped)
        self.assertIn("nonce", wrapped)
        self.assertIn("wrapped_key", wrapped)
        
        # Unwrap key
        unwrapped = unwrap_aes_key_with_ecc(
            receiver_priv,
            wrapped["ephemeral_pub"],
            wrapped["nonce"],
            wrapped["wrapped_key"]
        )
        self.assertEqual(unwrapped, aes_key)

    def test_hmac_computation_and_verification(self):
        """Test HMAC computation and verification."""
        key = generate_aes_key()
        data = b"Test data"
        
        # Compute HMAC
        tag = compute_hmac(key, data)
        
        # Verify HMAC
        is_valid = verify_hmac(key, data, tag)
        self.assertTrue(is_valid)

    def test_hmac_verification_fails_with_tampered_data(self):
        """Test that HMAC verification fails with tampered data."""
        key = generate_aes_key()
        data = b"Test data"
        
        tag = compute_hmac(key, data)
        
        # Tamper with data
        tampered_data = b"Tampered data"
        is_valid = verify_hmac(key, tampered_data, tag)
        self.assertFalse(is_valid)

    def test_base64_encoding(self):
        """Test base64 encoding and decoding."""
        data = b"Test data with special chars: \x00\x01\x02"
        encoded = b64(data)
        decoded = ub64(encoded)
        self.assertEqual(decoded, data)


class TestIDSRuleEngine(unittest.TestCase):
    """Test IDS rule engine."""

    def setUp(self):
        """Set up test fixtures."""
        self.ids = IDSRuleEngine()
        self.ids.add_known_sender("alice@example.com")

    def test_safe_message(self):
        """Test that safe messages are not flagged."""
        context = {
            "sender_id": "alice@example.com",
            "ciphertext_b64": b64(b"x" * 100),
            "hmac_b64": b64(b"valid_hmac")
        }
        
        is_suspicious, triggers = self.ids.evaluate(context)
        self.assertFalse(is_suspicious)
        self.assertEqual(len(triggers), 0)

    def test_unknown_sender_detection(self):
        """Test detection of unknown senders."""
        context = {
            "sender_id": "unknown@attacker.com",
            "ciphertext_b64": b64(b"x" * 100),
            "hmac_b64": b64(b"valid_hmac")
        }
        
        is_suspicious, triggers = self.ids.evaluate(context)
        self.assertTrue(is_suspicious)
        self.assertIn("rule_unknown_sender", triggers)

    def test_missing_hmac_detection(self):
        """Test detection of missing HMAC."""
        context = {
            "sender_id": "alice@example.com",
            "ciphertext_b64": b64(b"x" * 100),
            "hmac_b64": ""
        }
        
        is_suspicious, triggers = self.ids.evaluate(context)
        self.assertTrue(is_suspicious)
        self.assertIn("rule_missing_integrity", triggers)

    def test_large_payload_detection(self):
        """Test detection of large payloads."""
        # Create payload larger than threshold (10 KB)
        large_payload = b"x" * (11 * 1024)
        
        context = {
            "sender_id": "alice@example.com",
            "ciphertext_b64": b64(large_payload),
            "hmac_b64": b64(b"valid_hmac")
        }
        
        is_suspicious, triggers = self.ids.evaluate(context)
        self.assertTrue(is_suspicious)
        self.assertIn("rule_large_payload", triggers)

    def test_rate_limiting(self):
        """Test rate limiting detection."""
        self.ids.update_config("max_requests_per_minute", 2)
        
        context = {
            "sender_id": "alice@example.com",
            "ciphertext_b64": b64(b"x" * 100),
            "hmac_b64": b64(b"valid_hmac")
        }
        
        # First two requests should be safe
        is_suspicious1, _ = self.ids.evaluate(context)
        self.assertFalse(is_suspicious1)
        
        is_suspicious2, _ = self.ids.evaluate(context)
        self.assertFalse(is_suspicious2)
        
        # Third request should trigger rate limit
        is_suspicious3, triggers = self.ids.evaluate(context)
        self.assertTrue(is_suspicious3)
        self.assertIn("rule_rapid_requests", triggers)

    def test_add_remove_known_sender(self):
        """Test adding and removing known senders."""
        new_sender = "bob@example.com"
        
        # Initially unknown
        context = {
            "sender_id": new_sender,
            "ciphertext_b64": b64(b"x" * 100),
            "hmac_b64": b64(b"valid_hmac")
        }
        is_suspicious1, _ = self.ids.evaluate(context)
        self.assertTrue(is_suspicious1)
        
        # Add to known senders
        self.ids.add_known_sender(new_sender)
        is_suspicious2, _ = self.ids.evaluate(context)
        self.assertFalse(is_suspicious2)
        
        # Remove from known senders
        self.ids.remove_known_sender(new_sender)
        is_suspicious3, _ = self.ids.evaluate(context)
        self.assertTrue(is_suspicious3)

    def test_get_stats(self):
        """Test getting IDS statistics."""
        stats = self.ids.get_stats()
        self.assertIn("known_senders_count", stats)
        self.assertIn("tracked_senders", stats)
        self.assertIn("config", stats)


class TestEntities(unittest.TestCase):
    """Test Sender, Receiver, and TTP entities."""

    def setUp(self):
        """Set up test fixtures."""
        self.sender = Sender("alice@example.com")
        self.receiver_priv, self.receiver_pub = generate_ecc_keypair()
        self.receiver_pub_bytes = serialize_public_key(self.receiver_pub)
        self.receiver = Receiver(self.receiver_priv)
        self.ttp = TTP(self.receiver_priv)

    def test_sender_prepare_package(self):
        """Test sender package preparation."""
        plaintext = b"Test message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        self.assertEqual(package["sender_id"], "alice@example.com")
        self.assertIn("enc_payload", package)
        self.assertIn("hmac_b64", package)
        self.assertIn("wrapped_key", package)

    def test_receiver_decrypt_valid_package(self):
        """Test receiver decryption of valid package."""
        plaintext = b"Test message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        result = self.receiver.try_decrypt(package)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["plaintext"], plaintext)

    def test_receiver_decrypt_tampered_package(self):
        """Test receiver detection of tampered package."""
        plaintext = b"Test message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        # Tamper with ciphertext
        ct_bytes = bytearray(ub64(package["enc_payload"]["ciphertext"]))
        ct_bytes[0] ^= 0x01
        package["enc_payload"]["ciphertext"] = b64(bytes(ct_bytes))
        
        result = self.receiver.try_decrypt(package)
        self.assertEqual(result["status"], "integrity_failed")

    def test_ttp_decrypt_for_audit(self):
        """Test TTP decryption for audit."""
        plaintext = b"Suspicious message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        result = self.ttp.decrypt_for_audit(package)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["plaintext"], plaintext)

    def test_ttp_audit_log(self):
        """Test TTP audit logging."""
        plaintext = b"Suspicious message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        self.ttp.decrypt_for_audit(package)
        
        audit_log = self.ttp.get_audit_log()
        self.assertEqual(len(audit_log), 1)
        self.assertEqual(audit_log[0]["sender"], "alice@example.com")
        self.assertEqual(audit_log[0]["status"], "decrypted")

    def test_complete_workflow_safe(self):
        """Test complete workflow for safe message."""
        plaintext = b"Safe message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        # IDS evaluation
        ids = IDSRuleEngine()
        ids.add_known_sender("alice@example.com")
        context = {
            "sender_id": package["sender_id"],
            "ciphertext_b64": package["enc_payload"]["ciphertext"],
            "hmac_b64": package.get("hmac_b64")
        }
        is_suspicious, _ = ids.evaluate(context)
        
        # Should not be suspicious
        self.assertFalse(is_suspicious)
        
        # Receiver decryption
        result = self.receiver.try_decrypt(package)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["plaintext"], plaintext)

    def test_complete_workflow_suspicious(self):
        """Test complete workflow for suspicious message."""
        plaintext = b"Suspicious message"
        package = self.sender.prepare_package(plaintext, self.receiver_pub_bytes)
        
        # IDS evaluation (sender not in known list)
        ids = IDSRuleEngine()
        context = {
            "sender_id": package["sender_id"],
            "ciphertext_b64": package["enc_payload"]["ciphertext"],
            "hmac_b64": package.get("hmac_b64")
        }
        is_suspicious, _ = ids.evaluate(context)
        
        # Should be suspicious
        self.assertTrue(is_suspicious)
        
        # TTP verification
        result = self.ttp.decrypt_for_audit(package)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["plaintext"], plaintext)


class TestEndToEnd(unittest.TestCase):
    """End-to-end integration tests."""

    def test_multiple_messages_between_parties(self):
        """Test multiple message exchanges."""
        sender = Sender("alice@example.com")
        receiver_priv, receiver_pub = generate_ecc_keypair()
        receiver_pub_bytes = serialize_public_key(receiver_pub)
        receiver = Receiver(receiver_priv)
        
        messages = [
            b"First message",
            b"Second message",
            b"Third message with special chars: \x00\x01\x02"
        ]
        
        for plaintext in messages:
            package = sender.prepare_package(plaintext, receiver_pub_bytes)
            result = receiver.try_decrypt(package)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["plaintext"], plaintext)

    def test_different_senders_same_receiver(self):
        """Test multiple senders to same receiver."""
        receiver_priv, receiver_pub = generate_ecc_keypair()
        receiver_pub_bytes = serialize_public_key(receiver_pub)
        receiver = Receiver(receiver_priv)
        
        senders = [
            Sender("alice@example.com"),
            Sender("bob@example.com"),
            Sender("charlie@example.com")
        ]
        
        for i, sender in enumerate(senders):
            plaintext = f"Message from sender {i}".encode()
            package = sender.prepare_package(plaintext, receiver_pub_bytes)
            result = receiver.try_decrypt(package)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["plaintext"], plaintext)


class TestIPValidation(unittest.TestCase):
    """Test IP address validation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.receiver_priv, self.receiver_pub = generate_ecc_keypair()
        self.receiver_pub_bytes = serialize_public_key(self.receiver_pub)

    def test_sender_with_ip_addresses(self):
        """Test Sender with IP addresses."""
        sender = Sender("alice@example.com", "192.168.1.100", "192.168.1.200")
        self.assertEqual(sender.sender_id, "alice@example.com")
        self.assertEqual(sender.sender_ip, "192.168.1.100")
        self.assertEqual(sender.receiver_ip, "192.168.1.200")

    def test_package_contains_ip_addresses(self):
        """Test that package contains IP addresses."""
        sender = Sender("alice@example.com", "192.168.1.100", "192.168.1.200")
        package = sender.prepare_package(b"test message", self.receiver_pub_bytes)
        
        self.assertIn("sender_ip", package)
        self.assertIn("receiver_ip", package)
        self.assertEqual(package["sender_ip"], "192.168.1.100")
        self.assertEqual(package["receiver_ip"], "192.168.1.200")

    def test_receiver_with_ip_address(self):
        """Test Receiver with IP address."""
        receiver = Receiver(self.receiver_priv, "192.168.1.200")
        self.assertEqual(receiver.receiver_ip, "192.168.1.200")

    def test_ip_validation_success(self):
        """Test successful IP validation."""
        sender = Sender("alice@example.com", "192.168.1.100", "192.168.1.200")
        receiver = Receiver(self.receiver_priv, "192.168.1.200")
        
        package = sender.prepare_package(b"test message", self.receiver_pub_bytes)
        result = receiver.try_decrypt(package, "192.168.1.100")
        
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["plaintext"], b"test message")

    def test_sender_ip_mismatch_detection(self):
        """Test sender IP mismatch detection."""
        sender = Sender("alice@example.com", "192.168.1.100", "192.168.1.200")
        receiver = Receiver(self.receiver_priv, "192.168.1.200")
        
        package = sender.prepare_package(b"test message", self.receiver_pub_bytes)
        result = receiver.try_decrypt(package, "10.0.0.1")  # Wrong IP
        
        self.assertEqual(result["status"], "ip_mismatch")
        self.assertIn("IP mismatch", result["error"])

    def test_ids_sender_ip_mismatch_rule(self):
        """Test IDS sender IP mismatch rule."""
        ids = IDSRuleEngine()
        
        context = {
            "sender_ip": "192.168.1.100",
            "expected_sender_ip": "10.0.0.1"
        }
        
        is_suspicious, triggers = ids.evaluate(context)
        self.assertTrue(is_suspicious)
        self.assertIn("rule_sender_ip_mismatch", triggers)

    def test_ids_receiver_ip_mismatch_rule(self):
        """Test IDS receiver IP mismatch rule."""
        ids = IDSRuleEngine()
        
        context = {
            "receiver_ip": "192.168.1.200",
            "expected_receiver_ip": "10.0.0.2"
        }
        
        is_suspicious, triggers = ids.evaluate(context)
        self.assertTrue(is_suspicious)
        self.assertIn("rule_receiver_ip_mismatch", triggers)

    def test_ids_ip_validation_success(self):
        """Test IDS IP validation success."""
        ids = IDSRuleEngine()
        
        context = {
            "sender_ip": "192.168.1.100",
            "expected_sender_ip": "192.168.1.100",
            "receiver_ip": "192.168.1.200",
            "expected_receiver_ip": "192.168.1.200"
        }
        
        is_suspicious, triggers = ids.evaluate(context)
        self.assertFalse(is_suspicious)
        self.assertEqual(len(triggers), 0)

    def test_ids_ip_validation_skip_when_missing(self):
        """Test IDS skips IP validation when IPs are missing."""
        ids = IDSRuleEngine()
        
        context = {
            "sender_ip": "192.168.1.100",
            # Missing expected_sender_ip
            "receiver_ip": "192.168.1.200",
            # Missing expected_receiver_ip
        }
        
        is_suspicious, triggers = ids.evaluate(context)
        self.assertFalse(is_suspicious)
        self.assertNotIn("rule_sender_ip_mismatch", triggers)
        self.assertNotIn("rule_receiver_ip_mismatch", triggers)


def run_tests():
    """Run all tests."""
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == "__main__":
    run_tests()
