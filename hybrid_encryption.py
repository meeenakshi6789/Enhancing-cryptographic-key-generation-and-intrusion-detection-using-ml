"""
Core hybrid encryption module.

Implements:
- AES-GCM encryption/decryption
- ECC key generation and serialization
- ECC-based AES key wrapping via ECDH + HKDF
- HMAC-SHA256 integrity verification
"""

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from typing import Dict, Any, Tuple


# ---------- Helpers ----------
def b64(x: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(x).decode()


def ub64(s: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(s.encode())


# ---------- ECC key generation & serialization ----------
def generate_ecc_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generate an ECC keypair using SECP384R1 curve.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key()
    return priv, pub


def serialize_public_key(pub: ec.EllipticCurvePublicKey) -> bytes:
    """
    Serialize ECC public key to uncompressed point format.
    
    Args:
        pub: ECC public key
        
    Returns:
        Serialized public key bytes
    """
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


def deserialize_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """
    Deserialize ECC public key from uncompressed point format.
    
    Args:
        data: Serialized public key bytes
        
    Returns:
        ECC public key object
    """
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), data)


# ---------- AES session key generation and AES-GCM encryption ----------
def generate_aes_key(length: int = 32) -> bytes:
    """
    Generate a random AES key.
    
    Args:
        length: Key length in bytes (default 32 = 256-bit)
        
    Returns:
        Random AES key bytes
    """
    return os.urandom(length)


def aes_encrypt(aes_key: bytes, plaintext: bytes) -> Dict[str, str]:
    """
    Encrypt plaintext using AES-GCM.
    
    Args:
        aes_key: AES encryption key (32 bytes for AES-256)
        plaintext: Data to encrypt
        
    Returns:
        Dict with base64-encoded nonce and ciphertext
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return {"nonce": b64(nonce), "ciphertext": b64(ct)}


def aes_decrypt(aes_key: bytes, nonce_b64: str, ct_b64: str) -> bytes:
    """
    Decrypt ciphertext using AES-GCM.
    
    Args:
        aes_key: AES decryption key
        nonce_b64: Base64-encoded nonce
        ct_b64: Base64-encoded ciphertext
        
    Returns:
        Decrypted plaintext
        
    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(ub64(nonce_b64), ub64(ct_b64), None)


# ---------- Wrap/unwrap AES key using ECC (ECDH -> HKDF -> AES-GCM) ----------
def wrap_aes_key_with_ecc(receiver_pub_bytes: bytes, aes_key: bytes) -> Dict[str, str]:
    """
    Wrap (encrypt) an AES key using receiver's ECC public key.
    
    Uses ephemeral ECDH key exchange to derive a symmetric wrapping key via HKDF,
    then encrypts the AES key with AES-GCM.
    
    Args:
        receiver_pub_bytes: Serialized receiver ECC public key
        aes_key: AES key to wrap
        
    Returns:
        Dict with ephemeral_pub, nonce, and wrapped_key (all base64-encoded)
    """
    # Generate ephemeral key
    ephemeral_priv = ec.generate_private_key(ec.SECP384R1())
    ephemeral_pub = ephemeral_priv.public_key()
    receiver_pub = deserialize_public_key(receiver_pub_bytes)

    # Perform ECDH
    shared = ephemeral_priv.exchange(ec.ECDH(), receiver_pub)
    
    # Derive wrapping key via HKDF
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecc-wrap-key"
    ).derive(shared)

    # Encrypt AES key with derived wrapping key
    aesgcm = AESGCM(wrap_key)
    nonce = os.urandom(12)
    wrapped = aesgcm.encrypt(nonce, aes_key, None)

    return {
        "ephemeral_pub": b64(serialize_public_key(ephemeral_pub)),
        "nonce": b64(nonce),
        "wrapped_key": b64(wrapped)
    }


def unwrap_aes_key_with_ecc(
    receiver_priv: ec.EllipticCurvePrivateKey,
    ephemeral_pub_b64: str,
    nonce_b64: str,
    wrapped_key_b64: str
) -> bytes:
    """
    Unwrap (decrypt) an AES key using receiver's ECC private key.
    
    Args:
        receiver_priv: Receiver's ECC private key
        ephemeral_pub_b64: Base64-encoded ephemeral public key
        nonce_b64: Base64-encoded nonce
        wrapped_key_b64: Base64-encoded wrapped key
        
    Returns:
        Decrypted AES key
        
    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    ephemeral_pub = deserialize_public_key(ub64(ephemeral_pub_b64))
    
    # Perform ECDH with ephemeral key
    shared = receiver_priv.exchange(ec.ECDH(), ephemeral_pub)
    
    # Derive wrapping key via HKDF
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecc-wrap-key"
    ).derive(shared)
    
    # Decrypt AES key
    aesgcm = AESGCM(wrap_key)
    aes_key = aesgcm.decrypt(ub64(nonce_b64), ub64(wrapped_key_b64), None)
    return aes_key


# ---------- Integrity: HMAC using AES session key ----------
def compute_hmac(aes_key: bytes, data: bytes) -> str:
    """
    Compute HMAC-SHA256 over data using AES key.
    
    Args:
        aes_key: Key for HMAC
        data: Data to authenticate
        
    Returns:
        Base64-encoded HMAC tag
    """
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(data)
    return b64(h.finalize())


def verify_hmac(aes_key: bytes, data: bytes, tag_b64: str) -> bool:
    """
    Verify HMAC-SHA256 tag over data.
    
    Args:
        aes_key: Key for HMAC
        data: Data to verify
        tag_b64: Base64-encoded HMAC tag
        
    Returns:
        True if tag is valid, False otherwise
    """
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(ub64(tag_b64))
        return True
    except Exception:
        return False
