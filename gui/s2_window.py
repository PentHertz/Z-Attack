"""
S2 Security Management Windows
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

import imgui
from config import cprint, Colors

# Try to import S2 support
try:
    from s2.s2_manager import s2_manager
    S2_AVAILABLE = True
except ImportError:
    S2_AVAILABLE = False


class S2Window:
    """S2 Security Manager window"""
    
    def __init__(self):
        self.visible = False
        self.selected_session = -1
    
    def show(self):
        self.visible = True
    
    def render(self):
        if not self.visible:
            return
        
        if not S2_AVAILABLE:
            return
        
        imgui.set_next_window_size(900, 600, imgui.ONCE)
        expanded, self.visible = imgui.begin("S2 Security Manager", True)
        
        if expanded:
            imgui.text_colored("S2 (Security 2) Session Management", 1.0, 0.8, 0.0)
            imgui.separator()
            
            # Session status
            imgui.text("Active S2 Sessions:")
            imgui.separator()
            
            imgui.begin_child("S2Sessions", width=0, height=200, border=True)
            if s2_manager.sessions:
                sessions = list(s2_manager.sessions.items())
                for i, (key, session) in enumerate(sessions):
                    has_dsk = session.dsk is not None
                    has_secret = session.shared_secret is not None
                    has_keys = len(session.ccm_keys) > 0
                    
                    status_color = (0.0, 1.0, 0.0) if (has_dsk and has_secret and has_keys) else (1.0, 0.5, 0.0)
                    
                    is_selected = self.selected_session == i
                    if imgui.selectable(f"Session: {key}##session_{i}", is_selected)[0]:
                        self.selected_session = i
                    
                    if imgui.is_item_hovered():
                        tooltip = f"Session: {key}\n"
                        tooltip += f"Has DSK: {'✓' if has_dsk else '✗'}\n"
                        tooltip += f"Has Shared Secret: {'✓' if has_secret else '✗'}\n"
                        tooltip += f"Derived Keys: {len(session.ccm_keys)}"
                        imgui.set_tooltip(tooltip)
                    
                    imgui.same_line(200)
                    imgui.push_style_color(imgui.COLOR_TEXT, *status_color)
                    imgui.text(f"DSK: {'✓' if has_dsk else '✗'}")
                    imgui.pop_style_color()
                    
                    imgui.same_line(280)
                    imgui.text(f"Secret: {'✓' if has_secret else '✗'}")
                    imgui.same_line(380)
                    imgui.text(f"Keys: {len(session.ccm_keys)}")
                    
                    if has_dsk and has_secret and has_keys:
                        imgui.same_line(450)
                        imgui.text_colored("READY TO DECRYPT", 0.0, 1.0, 0.0)
            else:
                imgui.text_colored("No active S2 sessions", 0.7, 0.7, 0.7)
            imgui.end_child()
            
            imgui.separator()
            
            # Captured data in 3 columns
            imgui.columns(3, "s2_data_columns")
            
            # Column 1: Known DSKs
            imgui.text("Known DSKs:")
            imgui.begin_child("DSKList", width=0, height=150, border=True)
            if s2_manager.known_dsks:
                for node_id, dsk in s2_manager.known_dsks.items():
                    imgui.text(f"Node {node_id}:")
                    imgui.text_colored(f"  {dsk.hex()}", 0.7, 1.0, 0.7)
            else:
                imgui.text_colored("No DSKs configured", 0.7, 0.7, 0.7)
                imgui.text("")
                imgui.text_colored("Use 'Add S2 DSK' menu", 0.5, 0.5, 1.0)
            imgui.end_child()
            
            imgui.next_column()
            
            # Column 2: Public Keys
            imgui.text("Captured Public Keys:")
            imgui.begin_child("PubKeyList", width=0, height=150, border=True)
            if s2_manager.captured_public_keys:
                for key, pubkey in s2_manager.captured_public_keys.items():
                    imgui.text(f"{key}:")
                    imgui.text_colored(f"  {pubkey.hex()[:32]}...", 0.7, 0.7, 1.0)
            else:
                imgui.text_colored("No public keys captured", 0.7, 0.7, 0.7)
            imgui.end_child()
            
            imgui.next_column()
            
            # Column 3: Nonces
            imgui.text("Captured S2 Nonces:")
            imgui.begin_child("S2NonceList", width=0, height=150, border=True)
            if s2_manager.captured_nonces:
                for key, nonce_data in s2_manager.captured_nonces.items():
                    imgui.text(f"{key}:")
                    imgui.text_colored(f"  {nonce_data['entropy'][:16]}...", 1.0, 0.7, 1.0)
            else:
                imgui.text_colored("No S2 nonces captured", 0.7, 0.7, 0.7)
            imgui.end_child()
            
            imgui.columns(1)
            
            imgui.separator()
            
            # Actions
            imgui.text("Actions:")
            if imgui.button("List Sessions (Console)", width=200):
                s2_manager.list_sessions()
            
            imgui.same_line()
            if imgui.button("Export Session Data", width=200):
                if s2_manager.export_session_data("output/s2_sessions.txt"):
                    cprint("[S2 GUI] Session data exported", Colors.OKGREEN, bold=True)
            
            imgui.same_line()
            if imgui.button("Clear All Sessions", width=200):
                s2_manager.sessions.clear()
                s2_manager.captured_public_keys.clear()
                s2_manager.captured_nonces.clear()
                s2_manager.kex_state.clear()
                cprint("[S2 Manager] All sessions cleared", Colors.WARNING, bold=True)
            
            imgui.separator()
            
            # Instructions
            imgui.text_colored("How to decrypt S2 traffic:", 1.0, 1.0, 0.0)
            imgui.text("1. Add device DSK using 'Add S2 DSK' menu (find on device label)")
            imgui.text("2. Capture full KEX exchange (when device joins network)")
            imgui.text("3. Tool will automatically decrypt subsequent messages")
            imgui.text("4. Check console output for decryption status")
            
        imgui.end()


class S2DSKWindow:
    """S2 DSK input window"""
    
    def __init__(self):
        self.visible = False
        self.dsk_input = ""
        self.node_input = ""
    
    def show(self):
        self.visible = True
    
    def render(self):
        if not self.visible:
            return
        
        if not S2_AVAILABLE:
            return
        
        imgui.set_next_window_size(600, 300, imgui.ONCE)
        expanded, self.visible = imgui.begin("Add S2 DSK", True)
        
        if expanded:
            imgui.text("Add Device Specific Key (DSK) for S2 Decryption")
            imgui.separator()
            
            imgui.text_colored("DSK is printed on device label or QR code", 0.7, 0.7, 0.7)
            imgui.text_colored("Format: 12345-67890-12345-67890-12345-67890-12345-67890", 0.7, 0.7, 0.7)
            imgui.text_colored("Or hex: 0102030405060708090a0b0c0d0e0f10", 0.7, 0.7, 0.7)
            imgui.separator()
            
            _, self.node_input = imgui.input_text("Node ID (hex)", self.node_input, 256)
            imgui.same_line()
            imgui.text_colored("Example: 02", 0.5, 0.5, 0.5)
            
            _, self.dsk_input = imgui.input_text("DSK", self.dsk_input, 256)
            
            imgui.text("")
            
            if imgui.button("Add DSK", width=150, height=40):
                if self.node_input and self.dsk_input:
                    success = s2_manager.add_dsk(self.node_input, self.dsk_input)
                    if success:
                        cprint(f"[GUI] DSK added for node {self.node_input}", Colors.OKGREEN, bold=True)
                        self.node_input = ""
                        self.dsk_input = ""
                else:
                    cprint("[GUI] Please enter both Node ID and DSK", Colors.FAIL)
            
            imgui.same_line()
            if imgui.button("Clear", width=150, height=40):
                self.node_input = ""
                self.dsk_input = ""
            
            imgui.separator()
            
            imgui.text("Currently Configured DSKs:")
            imgui.begin_child("CurrentDSKs", width=0, height=100, border=True)
            if s2_manager.known_dsks:
                for node_id, dsk in s2_manager.known_dsks.items():
                    imgui.text_colored(f"Node {node_id}: {dsk.hex()}", 0.0, 1.0, 0.0)
            else:
                imgui.text_colored("No DSKs configured yet", 0.7, 0.7, 0.7)
            imgui.end_child()
            
        imgui.end()
