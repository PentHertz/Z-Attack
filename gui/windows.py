"""
Popup windows for Z-Attack GUI
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
import datetime
import math
from typing import Optional
from config import cprint, Colors
from data import sendData
from .utils import load_texture

try:
    from s2.s2_window import S2Window
except ImportError:
    S2Window = None

try:
    from s2.s2_manager import s2_manager
    S2_AVAILABLE = True
except ImportError:
    S2_AVAILABLE = False

class SendWindow:
    """Advanced send frame window"""
    
    def __init__(self, network_manager, hardware_device, protocol, crypto):
        self.network_manager = network_manager
        self.hardware_device = hardware_device
        self.protocol = protocol
        self.crypto = crypto
        
        self.visible = False
        self.home_id = ""
        self.dst_node = ""
        self.src_node = ""
        self.payload = ""
        self.nonce = ""
        self.secure = False
        
        self.selected_home = -1
        self.selected_src = -1
        self.selected_dst = -1
        self.selected_cc = -1
    
    def show(self):
        """Show the window"""
        self.visible = True
    
    def render(self, log_manager):
        """Render the window"""
        if not self.visible:
            return
        
        imgui.set_next_window_size(1000, 700, imgui.ONCE)
        expanded, self.visible = imgui.begin("Send Frame (Advanced Mode)", True)
        
        if expanded:
            # Input section
            imgui.text("Emission:")
            imgui.separator()
            
            imgui.columns(2, "input_columns")
            _, self.home_id = imgui.input_text("HomeID", self.home_id, 256)
            imgui.next_column()
            _, self.dst_node = imgui.input_text("DstNode", self.dst_node, 256)
            imgui.columns(1)
            
            imgui.columns(2, "input_columns2")
            _, self.src_node = imgui.input_text("SrcNode", self.src_node, 256)
            imgui.next_column()
            _, self.payload = imgui.input_text("Payload", self.payload, 256)
            imgui.columns(1)
            
            _, self.nonce = imgui.input_text("Nonce", self.nonce, 256)
            _, self.secure = imgui.checkbox("Secure (Nonce required)", self.secure)
            
            if imgui.button("Send", width=200, height=40):
                self._send_frame(log_manager)
            
            imgui.separator()
            imgui.text("Selection:")
            imgui.separator()
            
            # Selection lists
            imgui.columns(4, "select_columns")
            
            # HomeID selection
            imgui.text("HomeID:")
            imgui.begin_child("HomeIDSelect", width=0, height=200, border=True)
            networks = self.network_manager.get_networks()
            home_ids = list(networks.keys())
            for i, hid in enumerate(home_ids):
                if imgui.selectable(hid, self.selected_home == i)[0]:
                    self.selected_home = i
                    self.home_id = hid
                    self.selected_src = -1
                    self.selected_dst = -1
            imgui.end_child()
            
            imgui.next_column()
            
            # Source node
            imgui.text("Source Node:")
            imgui.begin_child("SrcSelect", width=0, height=200, border=True)
            if 0 <= self.selected_home < len(home_ids):
                nodes = networks[home_ids[self.selected_home]]
                for i, node in enumerate(nodes):
                    if imgui.selectable(node[0], self.selected_src == i)[0]:
                        self.selected_src = i
                        self.src_node = node[0]
            imgui.end_child()
            
            imgui.next_column()
            
            # Destination node
            imgui.text("Dest Node:")
            imgui.begin_child("DstSelect", width=0, height=200, border=True)
            if 0 <= self.selected_home < len(home_ids):
                nodes = networks[home_ids[self.selected_home]]
                for i, node in enumerate(nodes):
                    if imgui.selectable(node[0], self.selected_dst == i)[0]:
                        self.selected_dst = i
                        self.dst_node = node[0]
            imgui.end_child()
            
            imgui.next_column()
            
            # Command class
            imgui.text("Command Class:")
            imgui.begin_child("CCSelect", width=0, height=200, border=True)
            try:
                cc_list = sorted(sendData.CmdClassToSend.keys())
                for i, cc_name in enumerate(cc_list):
                    if imgui.selectable(cc_name, self.selected_cc == i)[0]:
                        self.selected_cc = i
                        cc_value = sendData.CmdClassToSend[cc_name]
                        
                        # Convert to hex string
                        if isinstance(cc_value, bytes):
                            self.payload = cc_value.hex()
                        elif isinstance(cc_value, str):
                            try:
                                self.payload = cc_value.encode('latin-1').hex()
                            except:
                                self.payload = ''.join(c for c in cc_value 
                                                      if c in '0123456789abcdefABCDEF')
                        else:
                            try:
                                self.payload = bytes(cc_value).hex()
                            except:
                                self.payload = str(cc_value)
            except Exception as e:
                imgui.text(f"Error: {str(e)}")
            imgui.end_child()
            
            imgui.columns(1)
        
        imgui.end()

    def _send_frame(self, log_manager):
        """Send the frame"""
        try:
            # Validate inputs
            home_id_bytes = bytes.fromhex(self.home_id)
            src_bytes = bytes.fromhex(self.src_node)
            dst_bytes = bytes.fromhex(self.dst_node)
            payload_bytes = bytes.fromhex(self.payload)
            
            cprint("[*] Sending frame...", Colors.OKGREEN, bold=True)
            cprint(f"    HomeID: {self.home_id}", Colors.OKCYAN)
            cprint(f"    Src: {self.src_node} -> Dst: {self.dst_node}", Colors.OKCYAN)
            cprint(f"    Payload: {self.payload}", Colors.OKCYAN)
            
            # Encrypt if secure
            if self.secure and self.nonce:
                cprint("    [SECURE FRAME]", Colors.WARNING, bold=True)
                payload_bytes = self.crypto.encrypt_payload(
                    src_bytes, dst_bytes, payload_bytes, self.nonce
                )
            
            # Build frame
            frame = self.protocol.build_frame(
                self.home_id, self.src_node, self.dst_node, 
                payload_bytes, self.secure
            )
            
            # Debug output
            cprint(f"    -> Frame to send: {frame.hex()}", Colors.HEADER)
            
            # Send
            if self.hardware_device.transmit(frame):
                cprint("[*] Frame sent successfully", Colors.OKGREEN, bold=True)
                log_entry = f"HomeID:{self.home_id} Src:{self.src_node} "
                log_entry += f"Dst:{self.dst_node} Payload:{self.payload}"
                if self.secure:
                    log_entry = "SECURE - " + log_entry
                log_manager.add_send(log_entry, is_sent=True)
            else:
                cprint("[!] Send failed", Colors.FAIL, bold=True)
                
        except ValueError as e:
            cprint(f"[!] Invalid hex value: {e}", Colors.FAIL, bold=True)
        except Exception as e:
            cprint(f"[!] Send error: {e}", Colors.FAIL, bold=True)

class EasyWindow:
    """Easy mode send window"""
    
    def __init__(self, network_manager, hardware_device, protocol):
        self.network_manager = network_manager
        self.hardware_device = hardware_device
        self.protocol = protocol
        self.visible = False
        self.selected_home = -1
    
    def show(self):
        self.visible = True
    
    def render(self, log_manager):
        if not self.visible:
            return
        
        imgui.set_next_window_size(400, 200, imgui.ONCE)
        expanded, self.visible = imgui.begin("Send Frame (Easy Mode)", True)
        
        if expanded:
            networks = self.network_manager.get_networks()
            home_ids = list(networks.keys())
            
            if self.selected_home >= 0 and self.selected_home < len(home_ids):
                if imgui.button("Network Discovery"):
                    self._send_discovery(home_ids[self.selected_home], log_manager)
                
                if imgui.button("Turn On Lights"):
                    self._send_lights_on(home_ids[self.selected_home], log_manager)
                
                if imgui.button("Turn Off Lights"):
                    self._send_lights_off(home_ids[self.selected_home], log_manager)
            else:
                imgui.text("Please select a HomeID first")
        
        imgui.end()
    
    def _send_raw(self, home_id: str, payload: bytes, log_manager):
        """Send raw payload"""
        try:
            frame = bytes.fromhex(home_id) + payload
            checksum = self.protocol.calculate_checksum(b"\x00\x0E" + frame)
            frame = frame + bytes([checksum])
            
            if self.hardware_device.transmit(frame):
                log_manager.add_send(f"RAW - HomeID:{home_id} Payload:{payload.hex()}", True)
                cprint("[*] RAW frame sent", Colors.OKGREEN, bold=True)
        except Exception as e:
            cprint(f"[!] Send error: {e}", Colors.FAIL)
    
    def _send_discovery(self, home_id: str, log_manager):
        self._send_raw(home_id, b"\x01\x41\x01\x0e\xff\x72\x04\x00\x86", log_manager)
    
    def _send_lights_on(self, home_id: str, log_manager):
        self._send_raw(home_id, b"\x01\x41\x01\x0e\xff\x25\x01\xff\x4c", log_manager)
    
    def _send_lights_off(self, home_id: str, log_manager):
        self._send_raw(home_id, b"\x01\x41\x01\x0e\xff\x25\x01\x00\x4c", log_manager)


class KeyWindow:
    """AES key configuration window"""
    
    def __init__(self, crypto):
        self.crypto = crypto
        self.visible = False
        self.key_input = crypto.network_key
    
    def show(self):
        self.visible = True
    
    def render(self):
        if not self.visible:
            return
        
        imgui.set_next_window_size(500, 150, imgui.ONCE)
        expanded, self.visible = imgui.begin("AES Encryption", True)
        
        if expanded:
            imgui.text("Define Network Key to decrypt (default OZW):")
            _, self.key_input = imgui.input_text("Key", self.key_input, 256)
            
            if imgui.button("Define"):
                self.crypto.set_key(self.key_input)
                cprint(f"[KEY CHANGED] {self.key_input}", Colors.OKGREEN, bold=True)
        
        imgui.end()


class NonceWindow:
    """Captured nonces window"""
    
    def __init__(self):
        self.visible = False
    
    def show(self):
        self.visible = True
    
    def render(self, log_manager):
        if not self.visible:
            return
        
        imgui.set_next_window_size(800, 500, imgui.ONCE)
        expanded, self.visible = imgui.begin("Captured Nonces", True)
        
        if expanded:
            imgui.text("Captured Nonces Log:")
            imgui.text_colored("Right-click to copy NONCE VALUE only", 0.5, 0.5, 0.5)
            imgui.separator()
            
            imgui.begin_child("NonceLogScroll", width=0, height=350, border=True)
            for entry in log_manager.nonce_log:
                imgui.push_style_color(imgui.COLOR_TEXT, 0.8, 0.4, 1.0)
                imgui.selectable(entry, False)
                if imgui.is_item_hovered() and imgui.is_mouse_clicked(1):
                    if "Nonce:" in entry:
                        nonce_value = entry.split("Nonce:")[1].strip()
                        imgui.set_clipboard_text(nonce_value)
                    else:
                        imgui.set_clipboard_text(entry)
                imgui.pop_style_color()
            imgui.end_child()
            
            imgui.separator()
            imgui.text(f"Total captured: {len(log_manager.captured_nonces)} unique nonces")
            
            if imgui.button("Clear All Nonces"):
                log_manager.clear_nonces()
                cprint("[NONCES CLEARED]", Colors.WARNING, bold=True)
            
            imgui.same_line()
            if imgui.button("Export to File"):
                if log_manager.export_nonces():
                    imgui.text("Exported to output/captured_nonces.txt")
        
        imgui.end()


class DiscoveryWindow:
    """Network discovery and visualization window"""
    
    def __init__(self, network_manager):
        self.network_manager = network_manager
        self.visible = False
        self.selected_home = -1
    
    def show(self):
        self.visible = True
    
    def render(self):
        if not self.visible:
            return
        
        imgui.set_next_window_size(1000, 700, imgui.ONCE)
        expanded, self.visible = imgui.begin("Network Discovery - Interactive Map", True)
        
        if expanded:
            networks = self.network_manager.get_networks()
            home_ids = list(networks.keys())
            
            if 0 <= self.selected_home < len(home_ids):
                selected_home_id = home_ids[self.selected_home]
                
                imgui.text(f"Network Map for HomeID: {selected_home_id}")
                imgui.separator()
                
                # Interactive visual map
                self._render_network_map(selected_home_id, networks[selected_home_id])
                
                imgui.separator()
                
                # Export options
                imgui.text("Export Options:")
                if imgui.button("Generate Static Graph Image (Graphviz)", width=300):
                    self._export_graph(selected_home_id, networks[selected_home_id])
                
                imgui.same_line()
                imgui.text_colored("(Optional - requires Graphviz)", 0.6, 0.6, 0.6)
            else:
                imgui.text("Please select a HomeID first from the main window")
        
        imgui.end()
    
    def _render_network_map(self, home_id: str, nodes: list):
        """Render interactive network topology map"""
        imgui.text("Interactive Network Topology:")
        imgui.text_colored("Hover over nodes for details", 0.7, 0.7, 0.7)
        imgui.separator()
        
        draw_list = imgui.get_window_draw_list()
        canvas_pos = imgui.get_cursor_screen_pos()
        canvas_size = (950, 450)
        
        imgui.begin_child("NetworkCanvas", width=canvas_size[0], height=canvas_size[1], border=True)
        
        # Background
        draw_list.add_rect_filled(
            canvas_pos[0], canvas_pos[1],
            canvas_pos[0] + canvas_size[0], canvas_pos[1] + canvas_size[1],
            imgui.get_color_u32_rgba(0.05, 0.05, 0.05, 1.0)
        )
        
        # Find controller and other nodes
        controller_node = None
        other_nodes = []
        for node in nodes:
            if str(node[0]) == "01":
                controller_node = node
            else:
                other_nodes.append(node)
        
        # Layout parameters
        center_x = canvas_pos[0] + canvas_size[0] // 2
        center_y = canvas_pos[1] + canvas_size[1] // 2
        controller_radius = 50
        node_radius = 35
        orbit_radius = 150
        
        mouse_pos = imgui.get_mouse_pos()
        is_in_canvas = (canvas_pos[0] <= mouse_pos[0] <= canvas_pos[0] + canvas_size[0] and
                       canvas_pos[1] <= mouse_pos[1] <= canvas_pos[1] + canvas_size[1])
        
        # Draw connections
        if controller_node and other_nodes:
            for i, node in enumerate(other_nodes):
                angle = (2 * math.pi * i / len(other_nodes)) - (math.pi / 2)
                node_x = center_x + orbit_radius * math.cos(angle)
                node_y = center_y + orbit_radius * math.sin(angle)
                
                # Animated dashed line
                import time
                dash_offset = int(time.time() * 50) % 20
                distance = math.hypot(node_x - center_x, node_y - center_y)
                
                for d in range(0, int(distance), 20):
                    if (d + dash_offset) % 20 < 10:
                        t = d / distance
                        x1 = center_x + t * (node_x - center_x)
                        y1 = center_y + t * (node_y - center_y)
                        t2 = min(1.0, (d + 10) / distance)
                        x2 = center_x + t2 * (node_x - center_x)
                        y2 = center_y + t2 * (node_y - center_y)
                        draw_list.add_line(x1, y1, x2, y2, 
                                         imgui.get_color_u32_rgba(0.3, 0.6, 1.0, 0.6), 2.0)
        
        # Draw controller
        if controller_node:
            # Glow effect
            for glow in range(3):
                glow_size = controller_radius + (glow * 5)
                alpha = 0.15 - (glow * 0.04)
                draw_list.add_circle_filled(
                    center_x, center_y, glow_size,
                    imgui.get_color_u32_rgba(1.0, 0.2, 0.2, alpha), 32
                )
            
            # Controller circle
            draw_list.add_circle_filled(
                center_x, center_y, controller_radius,
                imgui.get_color_u32_rgba(0.8, 0.1, 0.1, 1.0), 32
            )
            draw_list.add_circle(
                center_x, center_y, controller_radius,
                imgui.get_color_u32_rgba(1.0, 0.3, 0.3, 1.0), 32, 3.0
            )
            
            # Star icon
            star_points = 5
            outer_r = controller_radius * 0.4
            inner_r = controller_radius * 0.2
            for i in range(star_points * 2):
                angle = (math.pi * i / star_points) - (math.pi / 2)
                r = outer_r if i % 2 == 0 else inner_r
                x = center_x + r * math.cos(angle)
                y = center_y + r * math.sin(angle)
                next_i = (i + 1) % (star_points * 2)
                next_angle = (math.pi * next_i / star_points) - (math.pi / 2)
                next_r = outer_r if next_i % 2 == 0 else inner_r
                next_x = center_x + next_r * math.cos(next_angle)
                next_y = center_y + next_r * math.sin(next_angle)
                draw_list.add_line(x, y, next_x, next_y,
                                 imgui.get_color_u32_rgba(1.0, 1.0, 0.3, 1.0), 2.0)
            
            # Text
            text = "CONTROLLER"
            text_size = imgui.calc_text_size(text)
            draw_list.add_text(
                center_x - text_size.x / 2, center_y + controller_radius + 5,
                imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), text
            )
            
            # Hover tooltip
            dist = math.hypot(mouse_pos[0] - center_x, mouse_pos[1] - center_y)
            if is_in_canvas and dist <= controller_radius:
                imgui.set_tooltip(f"HomeID: {home_id}\nNode: {controller_node[0]}\nType: Z-Wave Controller")
        
        # Draw other nodes
        for i, node in enumerate(other_nodes):
            angle = (2 * math.pi * i / len(other_nodes)) - (math.pi / 2)
            node_x = center_x + orbit_radius * math.cos(angle)
            node_y = center_y + orbit_radius * math.sin(angle)
            
            node_id = str(node[0])
            node_info = str(node[1]) if len(node) > 1 and node[1] else "Unknown Device"
            
            # Check hover
            dist = math.hypot(mouse_pos[0] - node_x, mouse_pos[1] - node_y)
            is_hovered = is_in_canvas and dist <= node_radius
            
            # Glow when hovered
            if is_hovered:
                for glow in range(3):
                    glow_size = node_radius + (glow * 4)
                    alpha = 0.2 - (glow * 0.05)
                    draw_list.add_circle_filled(
                        node_x, node_y, glow_size,
                        imgui.get_color_u32_rgba(0.3, 1.0, 0.3, alpha), 32
                    )
            
            # Node circle
            node_color = (0.2, 0.8, 0.2, 1.0) if is_hovered else (0.1, 0.6, 0.1, 1.0)
            draw_list.add_circle_filled(
                node_x, node_y, node_radius,
                imgui.get_color_u32_rgba(*node_color), 32
            )
            draw_list.add_circle(
                node_x, node_y, node_radius,
                imgui.get_color_u32_rgba(0.3, 1.0, 0.3, 1.0), 32, 2.5
            )
            
            # Chip icon
            chip_size = node_radius * 0.5
            draw_list.add_rect_filled(
                node_x - chip_size/2, node_y - chip_size/2,
                node_x + chip_size/2, node_y + chip_size/2,
                imgui.get_color_u32_rgba(0.2, 0.2, 0.2, 1.0)
            )
            
            # Text
            text = f"Node {node_id}"
            text_size = imgui.calc_text_size(text)
            draw_list.add_text(
                node_x - text_size.x / 2, node_y + node_radius + 5,
                imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), text
            )
            
            # Tooltip
            if is_hovered:
                imgui.set_tooltip(f"Node: {node_id}\nDevice: {node_info}\nHomeID: {home_id}")
        
        # Legend
        self._draw_legend(draw_list, canvas_pos, len(other_nodes), controller_node is not None)
        
        imgui.end_child()
    
    def _draw_legend(self, draw_list, canvas_pos, device_count, has_controller):
        """Draw legend and stats"""
        legend_x = canvas_pos[0] + 10
        legend_y = canvas_pos[1] + 10
        
        # Legend background
        draw_list.add_rect_filled(
            legend_x, legend_y, legend_x + 150, legend_y + 80,
            imgui.get_color_u32_rgba(0.1, 0.1, 0.1, 0.8)
        )
        draw_list.add_rect(
            legend_x, legend_y, legend_x + 150, legend_y + 80,
            imgui.get_color_u32_rgba(0.5, 0.5, 0.5, 1.0), 0.0, 0, 1.5
        )
        
        # Legend items
        draw_list.add_text(legend_x + 5, legend_y + 5,
                         imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Legend:")
        
        draw_list.add_circle_filled(legend_x + 15, legend_y + 30, 8,
                                   imgui.get_color_u32_rgba(0.8, 0.1, 0.1, 1.0), 16)
        draw_list.add_text(legend_x + 30, legend_y + 23,
                         imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Controller")
        
        draw_list.add_circle_filled(legend_x + 15, legend_y + 55, 8,
                                   imgui.get_color_u32_rgba(0.1, 0.6, 0.1, 1.0), 16)
        draw_list.add_text(legend_x + 30, legend_y + 48,
                         imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Device")
        
        # Stats
        stats_x = canvas_pos[0] + 950 - 160
        stats_y = canvas_pos[1] + 10
        draw_list.add_rect_filled(
            stats_x, stats_y, stats_x + 150, stats_y + 60,
            imgui.get_color_u32_rgba(0.1, 0.1, 0.1, 0.8)
        )
        draw_list.add_text(stats_x + 5, stats_y + 5,
                         imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Network Stats:")
        draw_list.add_text(stats_x + 5, stats_y + 25,
                         imgui.get_color_u32_rgba(0.7, 0.7, 1.0, 1.0), 
                         f"Total Devices: {device_count}")
        draw_list.add_text(stats_x + 5, stats_y + 40,
                         imgui.get_color_u32_rgba(0.7, 1.0, 0.7, 1.0), 
                         f"Controllers: {1 if has_controller else 0}")
    
    def _export_graph(self, home_id: str, nodes: list):
        """Export network graph using Graphviz"""
        try:
            import pydot
            import os
            
            os.makedirs("discovery", exist_ok=True)
            
            graph = pydot.Dot(graph_type='digraph')
            graph.set_bgcolor('white')
            
            # Create controller node
            controller = None
            for node in nodes:
                if str(node[0]) == "01":
                    controller = pydot.Node(f"HomeID {home_id}", 
                                          style="filled", fillcolor="red")
                    graph.add_node(controller)
                    break
            
            # Add other nodes
            if controller:
                for node in nodes:
                    if str(node[0]) != "01":
                        label = f"NodeID {node[0]}"
                        if len(node) > 1 and node[1]:
                            label += f"\\n{node[1]}"
                        device_node = pydot.Node(label, style="filled", fillcolor="lightgreen")
                        graph.add_node(device_node)
                        graph.add_edge(pydot.Edge(controller, device_node))
            
            output_path = f"discovery/{home_id}_graph.png"
            graph.write_png(output_path)
            cprint(f"Graph saved to: {output_path}", Colors.OKGREEN, bold=True)
            
        except ImportError:
            cprint("Graphviz not found! Install it to use this feature", Colors.FAIL, bold=True)
        except Exception as e:
            cprint(f"Error generating graph: {e}", Colors.WARNING, bold=True)

class AboutWindow:
    """About window"""
    
    def __init__(self):
        self.visible = False
        self.logo_texture = None
        self.logo_width = 0
        self.logo_height = 0
        self.logo_loaded = False  # Track if we've tried to load
    
    def show(self):
        self.visible = True
    
    def _load_logo(self):
        """Load Penthertz logo (called only once when window first opens)"""
        if self.logo_loaded:
            return
        
        self.logo_loaded = True
        
        try:
            result = load_texture("images/penthertz.png")
            
            if result is None or result[0] is None:
                cprint("[About] Failed to load logo", Colors.WARNING)
                return
            
            self.logo_texture, self.logo_width, self.logo_height = result
            #cprint(f"[About] Logo loaded: {self.logo_width}x{self.logo_height}, ID={self.logo_texture}", Colors.OKGREEN)
            
            # Scale down if too large
            max_width = 250
            if self.logo_width > max_width:
                scale = max_width / self.logo_width
                self.logo_width = int(self.logo_width * scale)
                self.logo_height = int(self.logo_height * scale)
                
        except Exception as e:
            cprint(f"[About] Exception loading logo: {e}", Colors.FAIL)
            import traceback
            traceback.print_exc()
    
    def render(self, s2_available):
        if not self.visible:
            return
        
        # Load logo on first render (when OpenGL context is ready)
        if not self.logo_loaded:
            self._load_logo()
        
        imgui.set_next_window_size(450, 400, imgui.ONCE)
        expanded, self.visible = imgui.begin("About Z-Attack-NG", True)
        
        if expanded:
            # Display Penthertz logo at the top
            if self.logo_texture is not None:
                # Center the image
                window_width = imgui.get_window_width()
                cursor_x = (window_width - self.logo_width) / 2
                imgui.set_cursor_pos_x(cursor_x)
                
                # Render image (same way as main logo)
                imgui.image(self.logo_texture, self.logo_width, self.logo_height)
                
                imgui.spacing()
                imgui.separator()
                imgui.spacing()
            
            # Main title
            imgui.push_font(None)  # You can add a larger font here if available
            title_text = "Z-Attack-NG 1.0"
            title_size = imgui.calc_text_size(title_text)
            window_width = imgui.get_window_width()
            imgui.set_cursor_pos_x((window_width - title_size.x) / 2)
            imgui.text_colored(title_text, 0.0, 1.0, 0.0)
            imgui.pop_font()
            
            imgui.spacing()
            
            # Subtitle
            subtitle = "Next Generation Z-Wave Security Tool"
            subtitle_size = imgui.calc_text_size(subtitle)
            imgui.set_cursor_pos_x((window_width - subtitle_size.x) / 2)
            imgui.text_colored(subtitle, 0.7, 0.7, 0.7)
            
            imgui.spacing()
            imgui.separator()
            imgui.spacing()
            
            # Credits section
            imgui.text_colored("Credits:", 1.0, 1.0, 0.0)
            imgui.bullet_text("Original Z-Attack by Advens (2015)")
            imgui.bullet_text("Refactored & Enhanced by Penthertz (2025)")
            
            imgui.spacing()
            
            # Website
            imgui.text_colored("Website: ", 0.7, 0.7, 0.7)
            imgui.same_line()
            imgui.text_colored("penthertz.com", 0.3, 0.7, 1.0)
            
            imgui.spacing()
            imgui.separator()
            imgui.spacing()
            
            # Features section
            imgui.text_colored("Features:", 1.0, 1.0, 0.0)
            imgui.bullet_text("Z-Wave S0 Security Analysis")
            
            # S2 Support with colored indicator
            imgui.bullet()
            imgui.same_line()
            imgui.text("Z-Wave S2 Security: ")
            imgui.same_line()
            if s2_available:
                imgui.text_colored("✓ Enabled", 0.0, 1.0, 0.0)
            else:
                imgui.text_colored("✗ Disabled", 1.0, 0.5, 0.0)
            
            imgui.bullet_text("Network Topology Mapping")
            imgui.bullet_text("Frame Injection & Analysis")
            imgui.bullet_text("Real-time Packet Decryption")
            
            imgui.spacing()
            imgui.separator()
            imgui.spacing()
            
            # Technology stack
            imgui.text_colored("Technologies:", 0.7, 0.7, 0.7)
            imgui.columns(2, "tech_columns")
            imgui.bullet_text("Python 3")
            imgui.bullet_text("ImGui Interface")
            imgui.next_column()
            imgui.bullet_text("RfCat / TI RF")
            imgui.bullet_text("AES Cryptography")
            imgui.columns(1)
            
            imgui.spacing()
            imgui.separator()
            imgui.spacing()
            
            # License
            license_text = "Licensed under GPLv3"
            license_size = imgui.calc_text_size(license_text)
            imgui.set_cursor_pos_x((window_width - license_size.x) / 2)
            imgui.text_colored(license_text, 0.5, 0.5, 0.5)
        
        imgui.end()

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
        
        try:
            from s2.s2_manager import s2_manager
        except ImportError:
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
        
        try:
            from s2.s2_manager import s2_manager
        except ImportError:
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
