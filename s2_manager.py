"""
S2 Security Integration Manager for Z-Attack
Handles S2 session management and frame processing

Author: Penthertz
License: GPLv3
"""

import datetime
from s2_crypto import S2SecurityManager, parse_s2_message_encap, extract_public_key_from_report, Colors, cprint

class S2SessionManager:
    """
    Manages S2 security sessions for multiple nodes
    Tracks KEX state, keys, and nonces
    """
    
    def __init__(self):
        """Initialize S2 Session Manager"""
        self.sessions = {}  # HomeID-NodeID -> S2SecurityManager
        self.kex_state = {}  # Track KEX progress
        self.captured_public_keys = {}
        self.captured_nonces = {}
        
        # User-provided DSKs
        self.known_dsks = {}  # NodeID -> DSK
        
        cprint("[S2 Manager] Initialized", Colors.OKGREEN, bold=True)
    
    def add_dsk(self, node_id, dsk):
        """
        Add a known DSK for a device
        
        Args:
            node_id: Node ID (hex string like "02")
            dsk: DSK string (e.g., "12345-67890-12345-67890-12345-67890-12345-67890")
        """
        try:
            # Convert DSK to bytes
            if isinstance(dsk, str):
                dsk = dsk.replace("-", "")
                if len(dsk) == 40:  # 20 bytes in hex
                    dsk = bytes.fromhex(dsk)
                elif len(dsk) == 32:  # 16 bytes in hex
                    dsk = bytes.fromhex(dsk)
            
            if len(dsk) != 16:
                cprint(f"[S2 Manager] Invalid DSK length: {len(dsk)} bytes", Colors.FAIL)
                return False
            
            self.known_dsks[node_id] = dsk
            cprint(f"[S2 Manager] DSK added for node {node_id}", Colors.OKGREEN)
            return True
            
        except Exception as e:
            cprint(f"[S2 Manager] Failed to add DSK: {e}", Colors.FAIL)
            return False
    
    def get_session(self, home_id, node_id):
        """Get or create S2 session for a node"""
        key = f"{home_id}-{node_id}"
        
        if key not in self.sessions:
            self.sessions[key] = S2SecurityManager()
            cprint(f"[S2 Manager] Created new session for {key}", Colors.OKCYAN)
        
        return self.sessions[key]
    
    def process_s2_frame(self, payload, home_id, src_node, dst_node):
        """
        Process incoming S2 frame
        
        Returns:
            Decrypted payload if successful, None otherwise
        """
        if len(payload) < 4:
            return None
        
        command_class = payload[0:2]
        command = payload[2:4]
        
        if command_class != "9f":
            return None
        
        # Get session for this node
        session = self.get_session(home_id, src_node)
        
        # Process different S2 commands
        if command == "05":  # KEX Report
            return self._process_kex_report(payload, home_id, src_node, session)
        
        elif command == "08":  # Public Key Report
            return self._process_public_key_report(payload, home_id, src_node, session)
        
        elif command == "02":  # Nonce Report
            return self._process_nonce_report(payload, home_id, src_node, session)
        
        elif command == "03":  # Message Encap
            return self._process_message_encap(payload, home_id, src_node, dst_node, session)
        
        elif command == "0a":  # Network Key Report
            return self._process_network_key_report(payload, home_id, src_node, session)
        
        return None
    
    def _process_kex_report(self, payload, home_id, node_id, session):
        """Process KEX Report"""
        try:
            kex_bytes = bytes.fromhex(payload[4:])
            kex_info = session.process_kex_report(kex_bytes)
            
            if kex_info:
                key = f"{home_id}-{node_id}"
                self.kex_state[key] = {
                    'timestamp': datetime.datetime.now(),
                    'kex_info': kex_info,
                    'state': 'kex_received'
                }
            
            return kex_info
            
        except Exception as e:
            cprint(f"[S2 Manager] KEX processing failed: {e}", Colors.FAIL)
            return None
    
    def _process_public_key_report(self, payload, home_id, node_id, session):
        """Process Public Key Report"""
        try:
            public_key = extract_public_key_from_report(bytes.fromhex(payload))
            
            if public_key:
                # Store public key
                key = f"{home_id}-{node_id}"
                self.captured_public_keys[key] = public_key
                
                # Set peer public key in session
                session.set_peer_public_key(public_key)
                
                # Check if we have DSK for this node
                if node_id in self.known_dsks:
                    session.set_dsk(self.known_dsks[node_id])
                    
                    # Generate our keypair if not done
                    if not session.public_key:
                        session.generate_keypair()
                    
                    # Compute shared secret
                    session.compute_shared_secret()
                    
                    cprint(f"[S2 Manager] Public key processed for {key}", Colors.OKGREEN)
                else:
                    cprint(f"[S2 Manager] Public key captured but no DSK available for node {node_id}", 
                           Colors.WARNING)
                    cprint(f"[S2 Manager] Use GUI to add DSK for decryption", Colors.WARNING)
                
                return public_key
            
        except Exception as e:
            cprint(f"[S2 Manager] Public key processing failed: {e}", Colors.FAIL)
            return None
    
    def _process_nonce_report(self, payload, home_id, node_id, session):
        """Process S2 Nonce Report"""
        try:
            # S2 Nonce format: Command Class + Command + Sequence + Entropy (8 bytes)
            if len(payload) < 22:  # 4 (header) + 16 (nonce data)
                return None
            
            sequence = payload[4:6]
            entropy = payload[6:22]
            
            key = f"{home_id}-{node_id}"
            self.captured_nonces[key] = {
                'timestamp': datetime.datetime.now(),
                'entropy': entropy,
                'sequence': sequence
            }
            
            cprint(f"[S2 Manager] Nonce captured for {key}", Colors.PURPLE)
            cprint(f"    Entropy: {entropy}", Colors.OKCYAN)
            
            return entropy
            
        except Exception as e:
            cprint(f"[S2 Manager] Nonce processing failed: {e}", Colors.FAIL)
            return None
    
    def _process_message_encap(self, payload, home_id, src_node, dst_node, session):
        """Process S2 Message Encapsulation (encrypted message)"""
        try:
            # Parse the frame
            parsed = parse_s2_message_encap(bytes.fromhex(payload))
            
            if not parsed:
                cprint("[S2 Manager] Failed to parse message encap", Colors.FAIL)
                return None
            
            cprint(f"[S2 Manager] Encrypted message detected", Colors.WARNING, bold=True)
            cprint(f"    Security Class: {parsed['security_class_name']}", Colors.OKCYAN)
            cprint(f"    Sequence: {parsed['sequence']}", Colors.OKCYAN)
            cprint(f"    SPAN: 0x{parsed['span']:02x}", Colors.OKCYAN)
            cprint(f"    Encrypted length: {len(parsed['encrypted_data'])} bytes", Colors.OKCYAN)
            
            # Check if we can decrypt
            if not session.shared_secret or not session.dsk:
                cprint("[S2 Manager] Cannot decrypt - missing shared secret or DSK", Colors.FAIL)
                cprint("[S2 Manager] Need to capture full KEX exchange + DSK", Colors.WARNING)
                return None
            
            # Check if we have keys for this security class
            sec_class = parsed['security_class']
            if sec_class not in session.ccm_keys:
                cprint(f"[S2 Manager] No keys derived for security class {sec_class}", Colors.FAIL)
                
                # Try to derive keys
                cprint(f"[S2 Manager] Attempting to derive keys...", Colors.WARNING)
                session.derive_network_key(sec_class)
                
                if sec_class not in session.ccm_keys:
                    cprint(f"[S2 Manager] Key derivation failed", Colors.FAIL)
                    return None
            
            # Verify SPAN (replay protection)
            if not session.verify_span(int(src_node, 16), parsed['span']):
                cprint("[S2 Manager] SPAN replay detected - potential attack!", Colors.FAIL, bold=True)
                return None
            
            # For decryption, we need the nonce
            # In S2, nonce is generated from sender and receiver entropy
            # We need to have captured both nonces
            
            # Try to find nonces
            sender_key = f"{home_id}-{src_node}"
            receiver_key = f"{home_id}-{dst_node}"
            
            if sender_key not in self.captured_nonces or receiver_key not in self.captured_nonces:
                cprint("[S2 Manager] Missing nonces for decryption", Colors.FAIL)
                cprint("[S2 Manager] Need both sender and receiver nonces", Colors.WARNING)
                return None
            
            sender_ei = bytes.fromhex(self.captured_nonces[sender_key]['entropy'])
            receiver_ei = bytes.fromhex(self.captured_nonces[receiver_key]['entropy'])
            
            # Generate nonce
            nonce = session.generate_nonce(sender_ei, receiver_ei, sec_class)
            
            if not nonce:
                cprint("[S2 Manager] Failed to generate nonce", Colors.FAIL)
                return None
            
            # Decrypt the message
            ciphertext_with_tag = parsed['encrypted_data'] + parsed['auth_tag']
            
            plaintext = session.decrypt_message(
                ciphertext_with_tag,
                nonce,
                sec_class,
                int(src_node, 16),
                int(dst_node, 16)
            )
            
            if plaintext:
                cprint("[S2 Manager] ✓✓✓ S2 DECRYPTION SUCCESSFUL ✓✓✓", Colors.OKGREEN, bold=True)
                return plaintext.hex()
            else:
                cprint("[S2 Manager] Decryption failed", Colors.FAIL)
                return None
            
        except Exception as e:
            cprint(f"[S2 Manager] Message encap processing failed: {e}", Colors.FAIL)
            import traceback
            traceback.print_exc()
            return None
    
    def _process_network_key_report(self, payload, home_id, node_id, session):
        """Process Network Key Report (during key grant)"""
        try:
            # This contains encrypted network key
            # Format: CC + CMD + Granted Keys + Encrypted Key
            if len(payload) < 40:
                return None
            
            granted_keys = payload[4:6]
            encrypted_key = payload[6:38]  # 16 bytes encrypted
            
            cprint(f"[S2 Manager] Network Key Report", Colors.PURPLE)
            cprint(f"    Granted Keys: {granted_keys}", Colors.OKCYAN)
            cprint(f"    Encrypted Key: {encrypted_key}", Colors.OKCYAN)
            
            # Would need to decrypt this with temp key
            # This is part of the key exchange protocol
            
            return encrypted_key
            
        except Exception as e:
            cprint(f"[S2 Manager] Network key report processing failed: {e}", Colors.FAIL)
            return None
    
    def get_session_status(self, home_id, node_id):
        """Get status of S2 session"""
        key = f"{home_id}-{node_id}"
        
        status = {
            'session_exists': key in self.sessions,
            'has_dsk': node_id in self.known_dsks,
            'has_public_key': key in self.captured_public_keys,
            'has_nonce': key in self.captured_nonces,
            'has_shared_secret': False,
            'ready_to_decrypt': False
        }
        
        if key in self.sessions:
            session = self.sessions[key]
            status['has_shared_secret'] = session.shared_secret is not None
            status['ready_to_decrypt'] = (
                session.shared_secret is not None and 
                session.dsk is not None and 
                len(session.ccm_keys) > 0
            )
        
        return status
    
    def list_sessions(self):
        """List all active S2 sessions"""
        cprint("\n[S2 Manager] Active Sessions:", Colors.HEADER, bold=True)
        
        if not self.sessions:
            cprint("  No active sessions", Colors.WARNING)
            return
        
        for key, session in self.sessions.items():
            status = "Ready" if session.shared_secret and session.dsk else "Incomplete"
            color = Colors.OKGREEN if status == "Ready" else Colors.WARNING
            
            cprint(f"\n  Session: {key}", color, bold=True)
            cprint(f"    Status: {status}", color)
            cprint(f"    Has DSK: {session.dsk is not None}", Colors.OKCYAN)
            cprint(f"    Has Shared Secret: {session.shared_secret is not None}", Colors.OKCYAN)
            cprint(f"    Derived Keys: {len(session.ccm_keys)}", Colors.OKCYAN)
    
    def export_session_data(self, filename="s2_sessions.txt"):
        """Export session data for analysis"""
        try:
            with open(filename, "w") as f:
                f.write("Z-Attack S2 Session Data Export\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write("="*80 + "\n\n")
                
                f.write("Known DSKs:\n")
                for node_id, dsk in self.known_dsks.items():
                    f.write(f"  Node {node_id}: {dsk.hex()}\n")
                
                f.write("\nCaptured Public Keys:\n")
                for key, pubkey in self.captured_public_keys.items():
                    f.write(f"  {key}: {pubkey.hex()}\n")
                
                f.write("\nCaptured Nonces:\n")
                for key, nonce_data in self.captured_nonces.items():
                    f.write(f"  {key}: {nonce_data['entropy']}\n")
                
                f.write("\nSessions:\n")
                for key, session in self.sessions.items():
                    f.write(f"\n  {key}:\n")
                    f.write(f"    Has DSK: {session.dsk is not None}\n")
                    f.write(f"    Has Shared Secret: {session.shared_secret is not None}\n")
                    f.write(f"    Keys derived: {len(session.ccm_keys)}\n")
            
            cprint(f"[S2 Manager] Session data exported to {filename}", Colors.OKGREEN)
            return True
            
        except Exception as e:
            cprint(f"[S2 Manager] Export failed: {e}", Colors.FAIL)
            return False


# Global S2 manager instance
s2_manager = S2SessionManager()
