"""
Rule-based Intrusion Detection System (IDS) engine.

Evaluates security rules to classify messages as Safe or Suspicious.
Each rule returns True if it detects suspicious activity.
"""

from typing import Dict, Any, Tuple, List, Callable, Optional, Set
from hybrid_encryption import ub64
import time


class IDSRuleEngine:
    """
    Rule-based IDS that evaluates multiple security rules.
    
    If any rule triggers, the message is classified as Suspicious.
    Otherwise, it's classified as Safe.
    """

    def __init__(self, known_senders: Optional[Set[str]] = None):
        """Initialize the IDS engine with default rules and known senders.
        
        Args:
            known_senders: Set of known/trusted sender IDs
        """
        self.known_senders = set(known_senders) if known_senders else set()
        self._request_times = {}
        
        # Default configuration
        self.config = {
            "max_payload_size": 10 * 1024,  # 10 KB
            "entropy_threshold": 0.8,  # 80% unique bytes
            "request_window_seconds": 60,  # 1 minute
            "max_requests_per_minute": 20,  # 20 requests per minute
            "min_hmac_length": 32  # 256-bit HMAC
        }
        
        # Register rules (order matters!)
        self.rules: List[Callable] = [
            self.rule_unknown_sender,  # Check unknown senders first
            self.rule_sender_ip_mismatch,
            self.rule_receiver_ip_mismatch,
            self.rule_large_payload,
            self.rule_high_cipher_entropy,
            self.rule_missing_integrity,
            self.rule_rapid_requests,
            self.rule_invalid_base64
        ]

    def rule_sender_ip_mismatch(self, context: Dict[str, Any]) -> bool:
        """
        Detect sender IP address mismatch.
        
        Returns True if sender IP is provided but doesn't match expected IP.
        """
        try:
            sender_ip = context.get("sender_ip")
            expected_sender_ip = context.get("expected_sender_ip")
            
            if not sender_ip or not expected_sender_ip:
                return False  # Skip if IPs not provided
                
            return sender_ip != expected_sender_ip
        except Exception:
            return False

    def rule_receiver_ip_mismatch(self, context: Dict[str, Any]) -> bool:
        """
        Detect receiver IP address mismatch.
        
        Returns True if receiver IP is provided but doesn't match expected IP.
        """
        try:
            receiver_ip = context.get("receiver_ip")
            expected_receiver_ip = context.get("expected_receiver_ip")
            
            if not receiver_ip or not expected_receiver_ip:
                return False  # Skip if IPs not provided
                
            return receiver_ip != expected_receiver_ip
        except Exception:
            return False

    def rule_large_payload(self, context: Dict[str, Any]) -> bool:
        """
        Detect suspiciously large payloads.
        
        Returns True if ciphertext exceeds configured threshold.
        """
        try:
            ct_b64 = context.get("ciphertext_b64", "")
            if not ct_b64:
                return False
            ct_len = len(ub64(ct_b64))
            return ct_len > self.config["max_payload_size"]
        except Exception:
            return False

    def rule_high_cipher_entropy(self, context: Dict[str, Any]) -> bool:
        """
        Detect high entropy in ciphertext (potential encryption).
        
        Returns True if ciphertext has high entropy, which is normal for encrypted data.
        """
        try:
            # Skip this check for known senders
            sender_id = context.get("sender_id")
            if sender_id and sender_id in self.known_senders:
                return False
                
            ct_b64 = context.get("ciphertext_b64")
            if not ct_b64:
                return False
                
            ct = ub64(ct_b64)
            if not ct:
                return False
                
            # Calculate byte entropy (0-1.0)
            uniq = len(set(ct))
            entropy_ratio = uniq / max(1, len(ct))
            
            # High entropy is normal for encrypted data
            return entropy_ratio > self.config["entropy_threshold"]
        except Exception:
            return False

    def rule_unknown_sender(self, context: Dict[str, Any]) -> bool:
        """Check if sender is not in the known senders list."""
        sender_id = context.get("sender_id")
        if not sender_id:
            return True  # Missing sender ID is suspicious
            
        # If known_senders is empty, all senders are considered unknown
        if not self.known_senders:
            return True
            
        return sender_id not in self.known_senders

    def rule_missing_integrity(self, context: Dict[str, Any]) -> bool:
        """
        Detect missing HMAC integrity tag.
        
        Returns True if HMAC tag is absent.
        """
        return not bool(context.get("hmac_b64"))

    def rule_rapid_requests(self, context: Dict[str, Any]) -> bool:
        """
        Detect rapid requests from the same sender (rate limiting).
        
        Returns True if sender exceeds request threshold in time window.
        """
        try:
            sender = context.get("sender_id")
            if not sender or sender not in self._request_times:
                return False
            
            current_time = time.time()
            window_seconds = self.config["request_window_seconds"]
            max_requests = self.config["max_requests_per_minute"]
            
            # Count requests in current window
            recent_requests = [
                t for t in self._request_times[sender]
                if current_time - t < window_seconds
            ]
            
            # Check if we've exceeded the threshold
            return len(recent_requests) >= max_requests
        except Exception:
            return False

    def rule_invalid_base64(self, context: Dict[str, Any]) -> bool:
        """
        Detect invalid base64 encoding in ciphertext or HMAC.
        
        Returns True if base64 decoding fails.
        """
        try:
            ct_b64 = context.get("ciphertext_b64", "")
            hmac_b64 = context.get("hmac_b64", "")
            
            if ct_b64:
                ub64(ct_b64)
            if hmac_b64:
                ub64(hmac_b64)
            
            return False
        except Exception:
            return True

    def _update_request_tracking(self, sender_id: Optional[str]) -> None:
        """Update request tracking for rate limiting.
        
        Args:
            sender_id: ID of the sender making the request
        """
        if not sender_id:
            return
            
        current_time = time.time()
        window_seconds = self.config["request_window_seconds"]
        
        # Initialize if not exists
        if sender_id not in self._request_times:
            self._request_times[sender_id] = []
            
        # Clean old entries
        self._request_times[sender_id] = [
            t for t in self._request_times[sender_id]
            if current_time - t < window_seconds
        ]
            
        # Add current request
        self._request_times[sender_id].append(current_time)

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Evaluate all rules against the given context.
        
        Args:
            context: Dictionary containing message context
            
        Returns:
            Tuple of (is_suspicious, triggers) where:
            - is_suspicious: True if any rule triggered
            - triggers: List of rule names that triggered
        """
        triggers = []
        
        # Check all rules
        for rule in self.rules:
            try:
                if rule(context):
                    triggers.append(rule.__name__)
            except Exception as e:
                # If a rule fails, treat as suspicious
                triggers.append(f"{rule.__name__}_error")
        
        # Update request tracking after checking rules
        self._update_request_tracking(context.get("sender_id"))
                
        return len(triggers) > 0, triggers

    def add_known_sender(self, sender_id: str) -> None:
        """
        Add a sender to the trusted list.
        
        Args:
            sender_id: Email or identifier of trusted sender
        """
        self.known_senders.add(sender_id)

    def remove_known_sender(self, sender_id: str) -> None:
        """
        Remove a sender from the trusted list.
        
        Args:
            sender_id: Email or identifier of sender
        """
        self.known_senders.discard(sender_id)

    def update_config(self, key: str, value: Any) -> None:
        """
        Update a configuration threshold.
        
        Args:
            key: Configuration key (e.g., "max_payload_size")
            value: New value
        """
        if key in self.config:
            self.config[key] = value

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current IDS statistics.
        
        Returns:
            Dict with known senders count, request tracking info, etc.
        """
        return {
            "known_senders_count": len(self.known_senders),
            "tracked_senders": len(self._request_times),
            "config": self.config.copy()
        }
