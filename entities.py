"""
Core entities: Sender, Receiver, and Trusted Third Party (TTP).

These classes implement the main workflow for secure message exchange.
"""

from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from hybrid_encryption import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    compute_hmac,
    verify_hmac,
    wrap_aes_key_with_ecc,
    unwrap_aes_key_with_ecc,
    ub64
)


class Sender:
    """
    Sender entity that prepares encrypted packages.
    
    Responsibilities:
    - Generate AES session keys
    - Encrypt payloads with AES-GCM
    - Compute HMAC for integrity
    - Wrap AES keys using receiver's ECC public key
    """

    def __init__(self, sender_id: str, sender_ip: str = None, receiver_ip: str = None):
        """
        Initialize a Sender.
        
        Args:
            sender_id: Unique identifier for this sender (e.g., email address)
            sender_ip: IP address of the sender
            receiver_ip: IP address of the intended receiver
        """
        self.sender_id = sender_id
        self.sender_ip = sender_ip
        self.receiver_ip = receiver_ip

    def prepare_package(self, plaintext: bytes, receiver_pub_bytes: bytes) -> Dict[str, Any]:
        """
        Prepare an encrypted package for transmission.
        
        Workflow:
        1. Generate AES session key
        2. Encrypt plaintext with AES-GCM
        3. Compute HMAC over ciphertext
        4. Wrap AES key using receiver's ECC public key
        5. Assemble package with all components
        
        Args:
            plaintext: Data to encrypt
            receiver_pub_bytes: Receiver's serialized ECC public key
            
        Returns:
            Dict containing:
            - sender_id: Sender identifier
            - enc_payload: Encrypted payload (nonce + ciphertext)
            - hmac_b64: HMAC tag for integrity verification
            - wrapped_key: Wrapped AES key (ephemeral_pub + nonce + wrapped_key)
        """
        # 1. Generate AES session key
        aes_key = generate_aes_key()
        
        # 2. Encrypt payload
        enc = aes_encrypt(aes_key, plaintext)
        
        # 3. Compute HMAC over ciphertext
        hmac_tag = compute_hmac(aes_key, ub64(enc["ciphertext"]))
        
        # 4. Wrap AES key using receiver's public key
        wrapped = wrap_aes_key_with_ecc(receiver_pub_bytes, aes_key)
        
        # 5. Assemble package
        package = {
            "sender_id": self.sender_id,
            "sender_ip": self.sender_ip,
            "receiver_ip": self.receiver_ip,
            "enc_payload": enc,
            "hmac_b64": hmac_tag,
            "wrapped_key": wrapped
        }
        
        return package


class Receiver:
    """
    Receiver entity that decrypts packages.
    
    Responsibilities:
    - Unwrap AES keys using private key
    - Verify HMAC integrity
    - Decrypt payloads with AES-GCM
    """

    def __init__(self, priv_key: ec.EllipticCurvePrivateKey, receiver_ip: str = None):
        """
        Initialize a Receiver.
        
        Args:
            priv_key: Receiver's ECC private key
            receiver_ip: IP address of the receiver
        """
        self.priv = priv_key
        self.receiver_ip = receiver_ip

    def try_decrypt(self, package: Dict[str, Any], expected_sender_ip: str = None) -> Dict[str, Any]:
        """
        Attempt to decrypt a package.
        
        Workflow:
        1. Validate sender IP if provided
        2. Unwrap AES key using private key
        3. Verify HMAC integrity
        4. Decrypt payload with AES-GCM
        
        Args:
            package: Encrypted package from Sender
            expected_sender_ip: Expected IP address of the sender
            
        Returns:
            Dict with status and result:
            - status: "ok", "integrity_failed", "decrypt_error", or "ip_mismatch"
            - plaintext: Decrypted data (if status == "ok")
            - error: Error message (if status == "decrypt_error" or "ip_mismatch")
        """
        # 1. Validate sender IP if provided
        if expected_sender_ip and package.get("sender_ip"):
            if package["sender_ip"] != expected_sender_ip:
                return {"status": "ip_mismatch", "error": f"Sender IP mismatch. Expected: {expected_sender_ip}, Got: {package['sender_ip']}"}
        try:
            # 1. Unwrap AES key
            wk = package["wrapped_key"]
            aes_key = unwrap_aes_key_with_ecc(
                self.priv,
                wk["ephemeral_pub"],
                wk["nonce"],
                wk["wrapped_key"]
            )
            
            # 2. Verify HMAC integrity
            ct_b64 = package["enc_payload"]["ciphertext"]
            ok = verify_hmac(aes_key, ub64(ct_b64), package.get("hmac_b64", ""))
            if not ok:
                return {"status": "integrity_failed"}
            
            # 3. Decrypt payload
            pt = aes_decrypt(aes_key, package["enc_payload"]["nonce"], ct_b64)
            return {"status": "ok", "plaintext": pt}
            
        except Exception as e:
            return {"status": "decrypt_error", "error": str(e)}


class TTP:
    """
    Trusted Third Party (TTP) for verification and audit.
    
    In this implementation, TTP holds a copy of the receiver's private key
    and performs decryption when IDS flags a message as suspicious.
    
    WARNING: This is a centralized backdoor and should be carefully considered
    in production systems. Consider:
    - Threshold cryptography (Shamir secret sharing)
    - Key-splitting across multiple parties
    - Hardware Security Modules (HSM)
    - Never store unencrypted private keys
    
    Responsibilities:
    - Decrypt suspicious messages for audit
    - Verify integrity
    - Log audit trails
    - Generate alerts
    """

    def __init__(self, receiver_priv: ec.EllipticCurvePrivateKey):
        """
        Initialize TTP.
        
        Args:
            receiver_priv: Receiver's ECC private key (for audit decryption)
        """
        self.receiver_priv = receiver_priv
        self.audit_log = []

    def decrypt_for_audit(self, package: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt a suspicious message for audit purposes.
        
        Workflow:
        1. Unwrap AES key
        2. Verify HMAC integrity
        3. Decrypt payload
        4. Log audit entry
        
        Args:
            package: Encrypted package to audit
            
        Returns:
            Dict with status and result:
            - status: "ok", "integrity_failed", or "decrypt_error"
            - plaintext: Decrypted data (if status == "ok")
            - error: Error message (if status == "decrypt_error")
        """
        try:
            # 1. Unwrap AES key
            wk = package["wrapped_key"]
            aes_key = unwrap_aes_key_with_ecc(
                self.receiver_priv,
                wk["ephemeral_pub"],
                wk["nonce"],
                wk["wrapped_key"]
            )
            
            # 2. Verify HMAC integrity
            ct_b64 = package["enc_payload"]["ciphertext"]
            ok = verify_hmac(aes_key, ub64(ct_b64), package.get("hmac_b64", ""))
            if not ok:
                return {"status": "integrity_failed"}
            
            # 3. Decrypt payload
            pt = aes_decrypt(aes_key, package["enc_payload"]["nonce"], ct_b64)
            
            # 4. Log audit entry (without storing plaintext)
            audit_entry = {
                "timestamp": __import__("time").time(),
                "sender": package.get("sender_id"),
                "status": "decrypted",
                "payload_size": len(pt)
            }
            self.audit_log.append(audit_entry)
            
            return {"status": "ok", "plaintext": pt}
            
        except Exception as e:
            # Log failed audit attempt
            audit_entry = {
                "timestamp": __import__("time").time(),
                "sender": package.get("sender_id"),
                "status": "failed",
                "error": str(e)
            }
            self.audit_log.append(audit_entry)
            
            return {"status": "decrypt_error", "error": str(e)}

    def get_audit_log(self) -> list:
        """
        Retrieve audit log entries.
        
        Returns:
            List of audit entries
        """
        return self.audit_log.copy()

    def clear_audit_log(self) -> None:
        """Clear audit log (use with caution)."""
        self.audit_log.clear()
