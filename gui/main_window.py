"""
Main GUI window for Z-Attack
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
import glfw
import OpenGL.GL as gl
from imgui.integrations.glfw import GlfwRenderer
import sys
from typing import Optional
from config import cprint, Colors, WINDOW_WIDTH, WINDOW_HEIGHT, LOGO_PATH
from .utils import LogManager, load_texture
from .windows import (SendWindow, EasyWindow, KeyWindow, NonceWindow, 
                     DiscoveryWindow, AboutWindow)
from .s2_window import S2Window 


try:
    from s2.s2_manager import s2_manager
    from .s2_window import S2Window, S2DSKWindow  # Import both!
    S2_AVAILABLE = True
except ImportError as e:
    S2_AVAILABLE = False
    S2Window = None
    S2DSKWindow = None
    cprint(f"[S2] S2 support not available: {e}", Colors.WARNING)

# Try to import command class parser
try:
    from data import zwClasses
    ZWCLASSES_AVAILABLE = True
except ImportError:
    ZWCLASSES_AVAILABLE = False
    cprint("[WARNING] zwClasses not found - command class parsing disabled", Colors.WARNING)


class ZAttackGUI:
    """Main GUI application"""
    
    def __init__(self, hardware_device, protocol, crypto, network_manager, 
                 debug=False, csv_output=True):
        self.hardware_device = hardware_device
        self.protocol = protocol
        self.crypto = crypto
        self.network_manager = network_manager
        self.debug = debug
        self.csv_output = csv_output
        
        # GUI state
        self.log_manager = LogManager()
        self.selected_home = -1
        self.is_running = True
        
        # Windows
        self.send_window = SendWindow(network_manager, hardware_device, protocol, crypto)
        self.easy_window = EasyWindow(network_manager, hardware_device, protocol)
        self.key_window = KeyWindow(crypto)
        self.nonce_window = NonceWindow()
        self.discovery_window = DiscoveryWindow(network_manager)
        self.about_window = AboutWindow()

        if S2_AVAILABLE:
            self.s2_window = S2Window()
            self.s2_dsk_window = S2DSKWindow()
        else:
            self.s2_window = None
            self.s2_dsk_window = None

        # ImGui/GLFW
        self.window = None
        self.impl = None
        self.logo_texture = None
        self.logo_width = 0
        self.logo_height = 0
        
        # Initialize GUI
        self._init_gui()
    
    def _init_gui(self):
        """Initialize ImGui and GLFW"""
        if not glfw.init():
            cprint("Failed to initialize GLFW", Colors.FAIL, bold=True)
            sys.exit(1)
        
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
        glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
        glfw.window_hint(glfw.OPENGL_FORWARD_COMPAT, gl.GL_TRUE)
        
        self.window = glfw.create_window(WINDOW_WIDTH, WINDOW_HEIGHT, 
                                        "Z-Attack - Z-Wave Security Tool", None, None)
        glfw.make_context_current(self.window)
        
        if not self.window:
            glfw.terminate()
            cprint("Failed to create window", Colors.FAIL, bold=True)
            sys.exit(1)
        
        imgui.create_context()
        self.impl = GlfwRenderer(self.window)
        
        # Load logo
        self.logo_texture, self.logo_width, self.logo_height = load_texture(LOGO_PATH)
        
        cprint("[GUI] Initialized successfully", Colors.OKGREEN, bold=True)
    
    def cleanup(self):
        """Clean up GUI resources"""
        if self.impl:
            cprint("[GUI] Shutting down ImGui...", Colors.OKCYAN)
            self.impl.shutdown()
        
        cprint("[GUI] Terminating GLFW...", Colors.OKCYAN)
        glfw.terminate()
        cprint("[GUI] Cleanup complete", Colors.OKGREEN)
    
    def run(self):
        """Main GUI loop"""
        while not glfw.window_should_close(self.window) and self.is_running:
            glfw.poll_events()
            self.impl.process_inputs()
            
            # Process Z-Wave packets
            self._process_packets()
            
            # Render GUI
            imgui.new_frame()
            self._render_main_window()
            self._render_sub_windows()
            imgui.render()
            
            gl.glClearColor(0.1, 0.1, 0.1, 1)
            gl.glClear(gl.GL_COLOR_BUFFER_BIT)
            
            self.impl.render(imgui.get_draw_data())
            glfw.swap_buffers(self.window)
    
    def _process_packets(self):
        """Process incoming Z-Wave packets"""
        data = self.hardware_device.receive()
        if data:
            frame = self.protocol.parse_frame(data, self.debug)
            if frame:
                self._handle_frame(frame)
    
    def _handle_frame(self, frame):
        """Handle parsed Z-Wave frame"""
        home_id = frame['home_id']
        src_node = frame['src_node']
        dst_node = frame['dst_node']
        payload = frame['payload']
        
        cprint("", Colors.ENDC)
        cprint(str(frame['timestamp']), Colors.HEADER, bold=True)
        
        # Check for ACK
        if self.protocol.is_ack_frame(frame):
            cprint(f"    ACK response from {src_node} to {dst_node}", 
                   Colors.OKGREEN, bold=True)
            self.log_manager.add_send(f"ACK from {src_node} to {dst_node}", is_sent=False)
            entry = f"{self.protocol.frame_number}  |  {frame['timestamp']}  |  "
            entry += f"{home_id}  |  {src_node}  |  {dst_node}  |  ACK Response"
            self.log_manager.add_reception(entry)
            return
        
        if len(payload) < 4 or len(payload) > 256:
            return
        
        cprint("    Z-Wave frame:", Colors.HEADER, bold=True)
        cprint(f"        HomeID= {home_id}", Colors.OKCYAN)
        cprint(f"        SrcNode= {src_node}", Colors.OKCYAN)
        cprint(f"        DstNode= {dst_node}", Colors.OKCYAN)
        cprint(f"        Checksum= {frame['checksum']}", Colors.OKCYAN)
        
        if dst_node == "ff":
            cprint("        [*] Broadcast frame", Colors.WARNING, bold=True)
        
        # Update network topology
        self.network_manager.add_node(home_id, src_node)
        if dst_node != "ff":
            self.network_manager.add_node(home_id, dst_node)
        
        # Parse command class
        decoded = self._parse_command_class(payload, home_id, src_node)
        
        if decoded:
            self.protocol.frame_number += 1
            entry = f"{self.protocol.frame_number}  |  {frame['timestamp']}  |  "
            entry += f"{home_id}  |  {src_node}  |  {dst_node}  |  {decoded}"
            self.log_manager.add_reception(entry)
    
    def _parse_command_class(self, payload: str, home_id: str, src_node: str) -> Optional[str]:
        """Parse Z-Wave command class"""
        if len(payload) < 4:
            return f"RAW: {payload}"
        
        zw_class = payload[0:2]
        cmd_class = payload[2:4]
        
        # Handle S2 if available
        if zw_class == "9f" and S2_AVAILABLE:
            try:
                decrypted = s2_manager.process_s2_frame(payload, home_id, src_node, "01")
                if decrypted:
                    cprint("        [S2] ✓✓✓ DECRYPTED ✓✓✓", Colors.OKGREEN, bold=True)
                    payload = decrypted
                    return self._parse_command_class(decrypted, home_id, src_node)
            except Exception as e:
                if self.debug:
                    cprint(f"        [S2] Decryption failed: {e}", Colors.WARNING)
        
        # Parse using zwClasses if available
        if ZWCLASSES_AVAILABLE:
            try:
                if zw_class in zwClasses.ZwaveClass:
                    cc_name = zwClasses.ZwaveClass[zw_class]['name']
                    cprint(f"        CommandClass= {cc_name}", Colors.HEADER)
                    
                    if cmd_class in zwClasses.ZwaveClass[zw_class]:
                        cmd_name = zwClasses.ZwaveClass[zw_class][cmd_class]
                        cprint(f"        Command= {cmd_name}", Colors.OKBLUE)
                        
                        result = f"{cc_name}  |  {cmd_name}("
                        
                        # Special handling for specific commands
                        result = self._handle_special_commands(
                            zw_class, cmd_class, cmd_name, payload, home_id, src_node, result
                        )
                        
                        result += ")"
                        return result
                    else:
                        return f"{cc_name}  |  UNKNOWN_CMD_{cmd_class}"
                else:
                    return f"UNKNOWN_CC_{zw_class}  |  CMD_{cmd_class}"
            except Exception as e:
                if self.debug:
                    cprint(f"        Parse error: {e}", Colors.FAIL)
                return f"PARSE_ERROR: {str(e)}"
        else:
            # No parser available, just show raw
            return f"CC:{zw_class} CMD:{cmd_class} RAW:{payload}"
    
    def _handle_special_commands(self, zw_class, cmd_class, cmd_name, 
                                 payload, home_id, src_node, result):
        """Handle special command parsing"""
        
        # Security S0 - Nonce Report
        if cmd_name == "SecurityCmd_NonceReport":
            nonce = payload[4:20]
            cprint(f"        [NONCE] {nonce}", Colors.OKGREEN, bold=True)
            self.log_manager.add_nonce(home_id, src_node, nonce)
            result += nonce
        
        # Basic switch commands
        elif cmd_name in ["SwitchBinaryCmd_Set", "SwitchBinaryCmd_Report", 
                         "BasicCmd_Report", "BasicCmd_Set"]:
            param = payload[4:6]
            if param == "ff":
                cprint("        Param[1]= On", Colors.OKGREEN, bold=True)
                result += "On"
            elif param == "00":
                cprint("        Param[1]= Off", Colors.FAIL, bold=True)
                result += "Off"
        
        # Battery report
        elif cmd_name == "BatteryCmd_Report":
            param = payload[4:6]
            if param == "ff":
                result += "Battery = 0"
            else:
                result += f"Battery = {int(param, 16)}"
        
        # Manufacturer specific
        elif cmd_name == "ManufacturerSpecificCmd_Report":
            manufacturer = payload[4:8]
            product = payload[8:12]
            result += f"Manufacturer={manufacturer}|Product={product}"
        
        return result
    
    def _render_main_window(self):
        """Render main window"""
        imgui.set_next_window_position(0, 0)
        imgui.set_next_window_size(WINDOW_WIDTH, WINDOW_HEIGHT)
        imgui.begin("Z-Attack - Z-Wave Security Tool", 
                   flags=imgui.WINDOW_NO_RESIZE | imgui.WINDOW_NO_MOVE | imgui.WINDOW_MENU_BAR)
        
        # Menu bar
        if imgui.begin_menu_bar():
            if imgui.begin_menu("Menu"):
                if imgui.menu_item("Send Frame (Advanced)")[0]:
                    self.send_window.show()
                if imgui.menu_item("Send Frame (Easy)")[0]:
                    self.easy_window.show()
                if imgui.menu_item("Define AES Key")[0]:
                    self.key_window.show()
                if imgui.menu_item("Captured Nonces")[0]:
                    self.nonce_window.show()
                if imgui.menu_item("Network Map")[0]:
                    self.discovery_window.show()
                if S2_AVAILABLE:
                    if imgui.menu_item("S2 Security Manager")[0]:
                        self.s2_window.show()
                    if imgui.menu_item("Add S2 DSK")[0]:
                        self.s2_dsk_window.show()
                if imgui.menu_item("Quit")[0]:
                    self.is_running = False
                imgui.end_menu()
            
            if imgui.begin_menu("Help"):
                if imgui.menu_item("About")[0]:
                    self.about_window.show()
                imgui.end_menu()
            
            imgui.end_menu_bar()
        
        # Two column layout
        imgui.columns(2, "main_columns")
        imgui.set_column_width(0, 900)
        
        # Left: Logs
        self._render_logs()
        
        # Right: Network info
        imgui.next_column()
        self._render_network_info()
        
        imgui.columns(1)
        imgui.end()
    
    def _render_logs(self):
        """Render log panels"""
        # Reception log
        imgui.begin_child("Reception", width=0, height=350, border=True)
        imgui.text("Reception Log:")
        imgui.same_line()
        imgui.text_colored("(Right-click to copy)", 0.5, 0.5, 0.5)
        imgui.separator()
        
        imgui.begin_child("LogScroll", width=0, height=0, border=False)
        for entry in self.log_manager.reception_log:
            imgui.selectable(entry, False)
            if imgui.is_item_hovered() and imgui.is_mouse_clicked(1):
                imgui.set_clipboard_text(entry)
        imgui.end_child()
        imgui.end_child()
        
        # Send log
        imgui.begin_child("SendLog", width=0, height=380, border=True)
        imgui.text("Send/Response Log:")
        imgui.same_line()
        imgui.text_colored("(Right-click to copy)", 0.5, 0.5, 0.5)
        imgui.separator()
        
        imgui.begin_child("SendLogScroll", width=0, height=0, border=False)
        for entry in self.log_manager.send_log:
            if "[SENT]" in entry:
                imgui.push_style_color(imgui.COLOR_TEXT, 1.0, 0.647, 0.0)
            else:
                imgui.push_style_color(imgui.COLOR_TEXT, 0.0, 1.0, 1.0)
            imgui.selectable(entry, False)
            if imgui.is_item_hovered() and imgui.is_mouse_clicked(1):
                imgui.set_clipboard_text(entry)
            imgui.pop_style_color()
        imgui.end_child()
        imgui.end_child()
    
    def _render_network_info(self):
        """Render network information panel"""
        imgui.begin_child("RightPanel", width=0, height=0, border=False)
        
        # Logo
        if self.logo_texture:
            imgui.image(self.logo_texture, self.logo_width, self.logo_height)
       
        if S2_AVAILABLE:
            imgui.text_colored("S2 Security: ENABLED", 0.0, 1.0, 0.0)
            imgui.text(f"Active Sessions: {len(s2_manager.sessions)}")
            imgui.text(f"Known DSKs: {len(s2_manager.known_dsks)}")
        else:
            imgui.text_colored("S2 Security: DISABLED", 1.0, 0.5, 0.0)

        imgui.separator()

        imgui.text("Z-Wave Network Information")
        imgui.text("Home IDs Around You:")
        
        imgui.begin_child("HomeIDList", width=0, height=200, border=True)
        networks = self.network_manager.get_networks()
        home_ids = list(networks.keys())
        for i, hid in enumerate(home_ids):
            if imgui.selectable(hid, self.selected_home == i)[0]:
                self.selected_home = i
                self.send_window.selected_home = i
                self.easy_window.selected_home = i
                self.discovery_window.selected_home = i
        imgui.end_child()
        
        # Device info
        if 0 <= self.selected_home < len(home_ids):
            imgui.separator()
            imgui.text("Devices:")
            imgui.begin_child("DeviceList", width=0, height=0, border=True)
            nodes = networks[home_ids[self.selected_home]]
            for node in nodes:
                node_text = f"Node {node[0]}"
                if node[1]:
                    node_text += f": {node[1]}"
                imgui.text(node_text)
            imgui.end_child()
        
        imgui.end_child()
    
    def _render_sub_windows(self):
        """Render all sub-windows"""
        self.send_window.render(self.log_manager)
        self.easy_window.render(self.log_manager)
        self.key_window.render()
        self.nonce_window.render(self.log_manager)
        self.discovery_window.render()
        self.about_window.render(S2_AVAILABLE)
        if S2_AVAILABLE:
            if self.s2_window:
                self.s2_window.render()
            if self.s2_dsk_window:
                self.s2_dsk_window.render()
