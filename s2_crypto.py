"""
S2 Security Cryptography Module for Z-Attack
Implements Z-Wave S2 (Security 2) encryption/decryption

Requirements:
    pip install cryptography pycryptodomex

Author: Penthertz
License: GPLv3
"""

import hashlib
import hmac
import struct
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import secrets

# ANSI Colors for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    PURPLE = '\033[35m'

def cprint(text, color=Colors.ENDC, bold=False):
    """Colored print function"""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{text}{Colors.ENDC}")


class S2SecurityManager:
    """
    Manages S2 security operations including key exchange and encryption/decryption
    """
    
    # Security class identifiers
    S2_UNAUTHENTICATED = 0x00
    S2_AUTHENTICATED = 0x01
    S2_ACCESS_CONTROL = 0x02
    S0_LEGACY = 0x80
    
    # KEX schemes
    KEX_SCHEME_1 = 0x01
    
    # Curves
    CURVE_25519 = 0x01
    
    def __init__(self):
        """Initialize S2 Security Manager"""
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_secret = None
        self.dsk = None  # Device Specific Key
        
        # Derived keys for each security class
        self.network_keys = {}
        self.ccm_keys = {}
        self.nonce_keys = {}
        self.personalization_strings = {}
        
        # SPAN (Sender's Pseudo-random Nonce) tracking
        self.span_table = {}
        
        # KEX state
        self.kex_complete = False
        
        cprint("[S2] Security Manager initialized", Colors.OKGREEN)
    
    def generate_keypair(self):
        """Generate ECDH Curve25519 key pair"""
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        public_bytes = self.public_key.public_bytes_raw()
        cprint(f"[S2] Generated ECDH keypair", Colors.OKGREEN)
        cprint(f"    Public Key: {public_bytes.hex()}", Colors.OKCYAN)
        return public_bytes
    
    def set_peer_public_key(self, peer_public_bytes):
        """Set peer's public key from bytes"""
        try:
            self.peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
            cprint(f"[S2] Peer public key set: {peer_public_bytes.hex()}", Colors.OKGREEN)
            return True
        except Exception as e:
            cprint(f"[S2 ERROR] Invalid peer public key: {e}", Colors.FAIL)
            return False
    
    def set_dsk(self, dsk_bytes):
        """
        Set Device Specific Key (DSK)
        DSK is 16 bytes, usually displayed as 5-digit groups
        Example: 12345-67890-12345-67890-12345-67890-12345-67890
        """
        if isinstance(dsk_bytes, str):
            # Remove dashes and convert
            dsk_bytes = dsk_bytes.replace("-", "")
            if len(dsk_bytes) == 40:  # 5 groups of 8 hex chars
                dsk_bytes = bytes.fromhex(dsk_bytes)
            else:
                cprint(f"[S2 ERROR] Invalid DSK format", Colors.FAIL)
                return False
        
        if len(dsk_bytes) != 16:
            cprint(f"[S2 ERROR] DSK must be 16 bytes, got {len(dsk_bytes)}", Colors.FAIL)
            return False
        
        self.dsk = dsk_bytes
        cprint(f"[S2] DSK set: {dsk_bytes.hex()}", Colors.OKGREEN)
        return True
    
    def compute_shared_secret(self):
        """Compute ECDH shared secret"""
        if not self.private_key or not self.peer_public_key:
            cprint("[S2 ERROR] Keys not set for shared secret computation", Colors.FAIL)
            return None
        
        try:
            self.shared_secret = self.private_key.exchange(self.peer_public_key)
            cprint(f"[S2] Shared secret computed: {self.shared_secret.hex()}", Colors.OKGREEN)
            return self.shared_secret
        except Exception as e:
            cprint(f"[S2 ERROR] Failed to compute shared secret: {e}", Colors.FAIL)
            return None
    
    def derive_network_key(self, security_class, temp_key_expand=None):
        """
        Derive network key for a specific security class using HKDF
        
        Args:
            security_class: S2 security class (0x00, 0x01, 0x02)
            temp_key_expand: Temporary key expansion value (from KEX)
        """
        if not self.shared_secret or not self.dsk:
            cprint("[S2 ERROR] Shared secret and DSK required for key derivation", Colors.FAIL)
            return None
        
        try:
            # Construct info string for HKDF
            # Format: "TempKey" || security_class || temp_key_expand
            info = b"TempKey" + bytes([security_class])
            if temp_key_expand:
                info += temp_key_expand
            
            # HKDF with SHA-256
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=16,  # 128-bit key
                salt=self.dsk,  # DSK is used as salt
                info=info,
                backend=default_backend()
            )
            
            network_key = hkdf.derive(self.shared_secret)
            self.network_keys[security_class] = network_key
            
            cprint(f"[S2] Network key derived for class {security_class:02x}: {network_key.hex()}", 
                   Colors.OKGREEN)
            
            # Derive CCM key and Nonce key
            self._derive_ccm_keys(security_class, network_key)
            
            return network_key
            
        except Exception as e:
            cprint(f"[S2 ERROR] Key derivation failed: {e}", Colors.FAIL)
            return None
    
    def _derive_ccm_keys(self, security_class, network_key):
        """
        Derive CCM encryption and nonce keys from network key
        
        CCM Key: Used for AES-CCM encryption
        Nonce Key: Used for generating Message Privacy Nonces
        """
        try:
            # Derive CCM Key (for encryption)
            ccm_constant = b'\x55' * 16  # Constant for CCM key
            cipher = AES.new(network_key, AES.MODE_ECB)
            ccm_key = cipher.encrypt(ccm_constant)
            self.ccm_keys[security_class] = ccm_key
            
            # Derive Nonce Key (for nonce generation)
            nonce_constant = b'\xAA' * 16  # Constant for nonce key
            nonce_key = cipher.encrypt(nonce_constant)
            self.nonce_keys[security_class] = nonce_key
            
            # Derive Personalization String
            pers_constant = b'\x26' * 16  # Constant for personalization
            personalization = cipher.encrypt(pers_constant)
            self.personalization_strings[security_class] = personalization
            
            cprint(f"[S2] CCM keys derived for class {security_class:02x}", Colors.OKCYAN)
            cprint(f"    CCM Key: {ccm_key.hex()}", Colors.OKCYAN)
            cprint(f"    Nonce Key: {nonce_key.hex()}", Colors.OKCYAN)
            
        except Exception as e:
            cprint(f"[S2 ERROR] CCM key derivation failed: {e}", Colors.FAIL)
    
    def generate_nonce(self, sender_ei, receiver_ei, security_class):
        """
        Generate S2 nonce (Message Privacy Nonce)
        
        Args:
            sender_ei: Sender's Entropy Input (8 bytes)
            receiver_ei: Receiver's Entropy Input (8 bytes)
            security_class: Security class
        
        Returns:
            13-byte nonce for AES-CCM
        """
        if security_class not in self.nonce_keys:
            cprint(f"[S2 ERROR] No nonce key for security class {security_class:02x}", Colors.FAIL)
            return None
        
        try:
            # Concatenate entropy inputs
            entropy = sender_ei + receiver_ei
            
            # Encrypt with nonce key to generate nonce
            cipher = AES.new(self.nonce_keys[security_class], AES.MODE_ECB)
            encrypted = cipher.encrypt(entropy)
            
            # Take first 13 bytes as nonce
            nonce = encrypted[:13]
            
            cprint(f"[S2] Generated nonce: {nonce.hex()}", Colors.OKCYAN)
            return nonce
            
        except Exception as e:
            cprint(f"[S2 ERROR] Nonce generation failed: {e}", Colors.FAIL)
            return None
    
    def encrypt_message(self, plaintext, nonce, security_class, sender_node, receiver_node):
        """
        Encrypt message using AES-CCM
        
        Args:
            plaintext: Message to encrypt (bytes)
            nonce: 13-byte nonce
            security_class: Security class
            sender_node: Sender node ID
            receiver_node: Receiver node ID
        
        Returns:
            Encrypted message with authentication tag
        """
        if security_class not in self.ccm_keys:
            cprint(f"[S2 ERROR] No CCM key for security class {security_class:02x}", Colors.FAIL)
            return None
        
        try:
            # Additional Authenticated Data (AAD)
            # Format: sender || receiver || home_id || length || security_class
            # For simplicity, using sender and receiver
            aad = bytes([sender_node, receiver_node, len(plaintext), security_class])
            
            # AES-CCM encryption
            cipher = AES.new(
                self.ccm_keys[security_class],
                AES.MODE_CCM,
                nonce=nonce,
                mac_len=8  # 8-byte authentication tag
            )
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            
            cprint(f"[S2] Message encrypted, length: {len(ciphertext)} bytes", Colors.OKGREEN)
            cprint(f"    Auth Tag: {tag.hex()}", Colors.OKCYAN)
            
            return ciphertext + tag
            
        except Exception as e:
            cprint(f"[S2 ERROR] Encryption failed: {e}", Colors.FAIL)
            return None
    
    def decrypt_message(self, ciphertext_with_tag, nonce, security_class, sender_node, receiver_node):
        """
        Decrypt S2 encrypted message using AES-CCM
        
        Args:
            ciphertext_with_tag: Encrypted message with 8-byte auth tag
            nonce: 13-byte nonce
            security_class: Security class
            sender_node: Sender node ID
            receiver_node: Receiver node ID
        
        Returns:
            Decrypted plaintext or None if authentication fails
        """
        if security_class not in self.ccm_keys:
            cprint(f"[S2 ERROR] No CCM key for security class {security_class:02x}", Colors.FAIL)
            return None
        
        try:
            # Split ciphertext and tag
            if len(ciphertext_with_tag) < 8:
                cprint(f"[S2 ERROR] Message too short", Colors.FAIL)
                return None
            
            ciphertext = ciphertext_with_tag[:-8]
            tag = ciphertext_with_tag[-8:]
            
            cprint(f"[S2] Attempting decryption...", Colors.WARNING)
            cprint(f"    Ciphertext length: {len(ciphertext)} bytes", Colors.OKCYAN)
            cprint(f"    Auth Tag: {tag.hex()}", Colors.OKCYAN)
            cprint(f"    Nonce: {nonce.hex()}", Colors.OKCYAN)
            
            # Additional Authenticated Data (AAD)
            aad = bytes([sender_node, receiver_node, len(ciphertext), security_class])
            
            # AES-CCM decryption
            cipher = AES.new(
                self.ccm_keys[security_class],
                AES.MODE_CCM,
                nonce=nonce,
                mac_len=8
            )
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            cprint(f"[S2] ✓ Message decrypted successfully!", Colors.OKGREEN, bold=True)
            cprint(f"    Plaintext: {plaintext.hex()}", Colors.OKGREEN)
            
            return plaintext
            
        except ValueError as e:
            cprint(f"[S2 ERROR] Authentication failed - message tampered or wrong key", Colors.FAIL, bold=True)
            return None
        except Exception as e:
            cprint(f"[S2 ERROR] Decryption failed: {e}", Colors.FAIL)
            return None
    
    def process_kex_report(self, kex_data):
        """
        Process KEX Report message
        
        Format:
            - Request/Grant byte
            - KEX Schemes
            - ECDH Profiles  
            - Requested Keys
        """
        try:
            if len(kex_data) < 4:
                return None
            
            request_csa = kex_data[0]
            schemes = kex_data[1]
            curves = kex_data[2]
            keys = kex_data[3]
            
            cprint(f"[S2 KEX] Report received", Colors.PURPLE, bold=True)
            cprint(f"    Request/Grant: 0x{request_csa:02x}", Colors.OKCYAN)
            cprint(f"    Schemes: 0x{schemes:02x} (Scheme 1: {bool(schemes & 0x01)})", Colors.OKCYAN)
            cprint(f"    Curves: 0x{curves:02x} (Curve25519: {bool(curves & 0x01)})", Colors.OKCYAN)
            
            # Parse requested security classes
            sec_classes = []
            if keys & 0x80:
                sec_classes.append("S0 Legacy")
            if keys & 0x04:
                sec_classes.append("S2 Access Control")
            if keys & 0x02:
                sec_classes.append("S2 Authenticated")
            if keys & 0x01:
                sec_classes.append("S2 Unauthenticated")
            
            cprint(f"    Security Classes: {', '.join(sec_classes)}", Colors.OKGREEN)
            
            return {
                'request_csa': request_csa,
                'schemes': schemes,
                'curves': curves,
                'keys': keys,
                'security_classes': sec_classes
            }
            
        except Exception as e:
            cprint(f"[S2 ERROR] Failed to process KEX: {e}", Colors.FAIL)
            return None
    
    def extract_span(self, s2_frame):
        """
        Extract SPAN (Sender's Pseudo-random Nonce) from S2 frame
        SPAN is first byte after command class
        """
        try:
            if len(s2_frame) < 3:
                return None
            
            span = s2_frame[2]
            return span
            
        except Exception as e:
            cprint(f"[S2 ERROR] Failed to extract SPAN: {e}", Colors.FAIL)
            return None
    
    def verify_span(self, sender_node, span):
        """
        Verify SPAN hasn't been used before (replay protection)
        """
        key = f"{sender_node}"
        
        if key not in self.span_table:
            self.span_table[key] = set()
        
        if span in self.span_table[key]:
            cprint(f"[S2 WARN] SPAN replay detected! Node {sender_node}, SPAN {span}", 
                   Colors.FAIL, bold=True)
            return False
        
        self.span_table[key].add(span)
        return True
    
    def clear_span_table(self):
        """Clear SPAN table (for testing/reset)"""
        self.span_table = {}
        cprint("[S2] SPAN table cleared", Colors.WARNING)


# Helper functions for S2 frame parsing

def parse_s2_message_encap(payload):
    """
    Parse S2 Message Encapsulation frame
    
    Format:
        - Command Class (0x9F)
        - Command (0x03)
        - Sequence/Properties
        - SPAN
        - Encrypted payload
        - Authentication tag (8 bytes)
    """
    try:
        if len(payload) < 12:  # Minimum: CC + Cmd + Seq + SPAN + Tag
            return None
        
        sequence = payload[2]
        properties = sequence & 0x0F
        sequence_num = (sequence >> 4) & 0x0F
        
        # Extract security class from properties
        security_class_map = {
            0x00: "S2 Unauthenticated",
            0x01: "S2 Authenticated", 
            0x02: "S2 Access Control",
            0x03: "S0 Legacy"
        }
        
        sec_class = properties & 0x07
        security_class_name = security_class_map.get(sec_class, "Unknown")
        
        # SPAN (multicast flag | group_id | sequence)
        span = payload[3]
        
        # Encrypted payload and tag
        encrypted_data = payload[4:-8]
        auth_tag = payload[-8:]
        
        return {
            'sequence': sequence_num,
            'security_class': sec_class,
            'security_class_name': security_class_name,
            'span': span,
            'encrypted_data': encrypted_data,
            'auth_tag': auth_tag
        }
        
    except Exception as e:
        cprint(f"[S2 ERROR] Failed to parse message encap: {e}", Colors.FAIL)
        return None


def extract_public_key_from_report(payload):
    """
    Extract public key from S2 Public Key Report
    Public key is 32 bytes (Curve25519)
    """
    try:
        # Format: 0x9F 0x08 <32-byte public key>
        if len(payload) < 34:
            return None
        
        public_key = payload[2:34]
        return public_key
        
    except Exception as e:
        cprint(f"[S2 ERROR] Failed to extract public key: {e}", Colors.FAIL)
        return None
