"""
Z-Wave encryption and decryption (S0)
Next Generation Z-Wave Security Testing Tool

Original Z-Attack developed by Advens (2015)
https://github.com/Advens/Z-Attack

Refactored and Enhanced by Penthertz (2025)
- Complete code modernization and restructuring
- Modular architecture with separated GUI and logic
- Added S2 (Security 2) support
- Enhanced UI with ImGui
- Modern argument parsing
- Improved error handling and stability

Website: https://penthertz.com
License: GPLv3

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program comes with ABSOLUTELY NO WARRANTY.
"""

from typing import Optional
from Crypto.Cipher import AES
from config import cprint, Colors

class ZWaveCrypto:
    """Handles Z-Wave S0 encryption/decryption"""
    
    def __init__(self, network_key: str):
        self.network_key = network_key
    
    def set_key(self, key: str):
        """Set network key"""
        self.network_key = key
    
    def generate_encrypt_key(self) -> bytes:
        """Generate encryption key from network key"""
        temp_key = bytes.fromhex(self.network_key)
        msg = b'\xaa' * 16
        cipher = AES.new(temp_key, AES.MODE_ECB)
        return cipher.encrypt(msg)
    
    def generate_mac_key(self) -> bytes:
        """Generate MAC key from network key"""
        temp_key = bytes.fromhex(self.network_key)
        msg = b'\x55' * 16
        cipher = AES.new(temp_key, AES.MODE_ECB)
        return cipher.encrypt(msg)
    
    def encrypt_payload(self, src_node: bytes, dst_node: bytes, 
                       payload: bytes, nonce: str) -> bytes:
        """
        Encrypt payload using S0 security
        
        Args:
            src_node: Source node ID
            dst_node: Destination node ID
            payload: Plaintext payload
            nonce: Remote device nonce (16 hex chars)
            
        Returns:
            Encrypted frame
        """
        # Command class and sequence
        cc_msg_encap = b"\x98\x81"
        sequence = b"\x81"
        
        # Generate IV
        nonce_local = "aa" * 8
        nonce_id = nonce[:2]
        iv = nonce_local + nonce
        
        # Pad payload
        payload = b"\x00" + payload
        payload_hex = payload.hex()
        length_payload = len(payload_hex) // 2
        padding_length = 32 - (length_payload * 2)
        payload_padded = payload_hex + ("0" * padding_length)
        payload_bytes = bytes.fromhex(payload_padded)
        
        # Encrypt payload
        encrypt_key = self.generate_encrypt_key()
        cipher = AES.new(encrypt_key, AES.MODE_OFB, bytes.fromhex(iv))
        encrypted = cipher.encrypt(payload_bytes)
        encrypted = encrypted[:length_payload]
        
        # Generate MAC
        mac_raw = sequence.hex() + src_node.hex() + dst_node.hex()
        mac_raw += f"{length_payload:02x}" + encrypted.hex()
        
        auth_key = self.generate_mac_key()
        cipher = AES.new(auth_key, AES.MODE_ECB)
        temp_auth = cipher.encrypt(bytes.fromhex(iv))
        
        # Pad MAC
        mac_length = len(mac_raw) // 2
        padding_length = 32 - (mac_length * 2)
        mac_padded = mac_raw + ("0" * padding_length)
        
        # XOR with encrypted IV
        xored = int(mac_padded, 16) ^ int(temp_auth.hex(), 16)
        xored_hex = f"{xored:032x}"
        
        # Encrypt MAC
        cipher = AES.new(auth_key, AES.MODE_ECB)
        encoded_mac = cipher.encrypt(bytes.fromhex(xored_hex))
        encoded_mac = encoded_mac[:8]
        
        # Build final frame
        return cc_msg_encap + bytes.fromhex(nonce_local) + encrypted + bytes.fromhex(nonce_id) + encoded_mac
    
    def decrypt_payload(self, encrypted: str, nonce_device: str, 
                       nonce_remote: str, length: int, debug: bool = False) -> Optional[str]:
        """
        Decrypt S0 encrypted payload
        
        Args:
            encrypted: Encrypted payload hex string
            nonce_device: Device nonce (16 hex chars)
            nonce_remote: Remote nonce (16 hex chars)
            length: Length of encrypted data
            debug: Enable debug output
            
        Returns:
            Decrypted payload hex string or None
        """
        if len(self.network_key) != 32:
            cprint("    [ERROR] Invalid network key length", Colors.FAIL, bold=True)
            return None
        
        if not nonce_device or not nonce_remote:
            cprint("    [ERROR] Missing nonces", Colors.FAIL)
            return None
        
        try:
            encrypt_key = self.generate_encrypt_key()
            iv = nonce_device + nonce_remote
            
            # Handle multi-block encryption
            if length > 16 and length < 32:
                block1 = encrypted[0:32]
                block2 = encrypted[32:]
                
                # Pad block 2
                block2_len = len(block2) // 2
                padding = 32 - (block2_len * 2)
                block2 = block2 + ("0" * padding)
                
                # Decrypt both blocks
                cipher = AES.new(encrypt_key, AES.MODE_OFB, bytes.fromhex(iv))
                result1 = cipher.decrypt(bytes.fromhex(block1)).hex()
                result2 = cipher.decrypt(bytes.fromhex(block2)).hex()
                result = result1 + result2
            else:
                # Pad single block
                padding = 32 - (length * 2)
                encrypted_padded = encrypted + ("0" * padding)
                
                # Decrypt
                cipher = AES.new(encrypt_key, AES.MODE_OFB, bytes.fromhex(iv))
                result = cipher.decrypt(bytes.fromhex(encrypted_padded)).hex()
            
            if debug:
                cprint(f"    [DECRYPTED] {result}", Colors.OKGREEN, bold=True)
            
            return result[2:]  # Skip first byte
            
        except Exception as e:
            cprint(f"    [ERROR] Decryption failed: {e}", Colors.FAIL, bold=True)
            return None
