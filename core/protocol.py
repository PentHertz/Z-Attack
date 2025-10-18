"""
Z-Wave protocol handling and frame parsing
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

import re
import datetime
from typing import Optional, Dict, List, Tuple
from config import cprint, Colors

class ZWaveProtocol:
    """Handles Z-Wave protocol parsing and frame construction"""
    
    def __init__(self):
        self.frame_number = 0
    
    def parse_frame(self, data: bytes, debug: bool = False) -> Optional[Dict]:
        """Parse Z-Wave frame"""
        if not data or len(data) < 7:
            if debug:
                cprint(f"    [DEBUG] Frame too short: {len(data) if data else 0} bytes", Colors.WARNING)
            return None
        
        try:
            length = data[7] if isinstance(data[7], int) else ord(data[7])
            
            if debug:
                cprint(f"    [DEBUG] Frame length field: {length}, data length: {len(data)}", Colors.OKCYAN)
            
            # Get frame data
            res = data[0:length]
            
            # Extract checksum (last byte)
            fcs = res[-1:] if isinstance(res[-1], bytes) else bytes([res[-1]])
            fcs_int = fcs[0] if isinstance(fcs[0], int) else ord(fcs[0])
            
            # Remove checksum THEN calculate on remaining data
            res = res[:-1]
            calculated_checksum = self.calculate_checksum(res)
            
            if calculated_checksum != fcs_int:
                if debug:
                    cprint(f"    [DEBUG] Checksum mismatch: received={fcs.hex()} calculated={calculated_checksum:02x}", Colors.FAIL)
                return None
            
            if debug:
                cprint(f"    [DEBUG] Checksum OK: {fcs.hex()}", Colors.OKGREEN)
            
            # Convert to hex string
            hex_data = res.hex()
            
            # Remove noise patterns
            hex_data = re.sub(r'00[0-1][0-1][0-1][a-f0-9]', '', hex_data)
            hex_data = re.sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]00000', '', hex_data)
            hex_data = re.sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]', '', hex_data)
            
            if len(hex_data) < 18:
                if debug:
                    cprint(f"    [DEBUG] Hex data too short after cleanup: {len(hex_data)}", Colors.WARNING)
                return None
            
            return {
                'home_id': hex_data[0:8],
                'src_node': hex_data[8:10],
                'frame_control': hex_data[10:14],
                'length': hex_data[14:16],
                'dst_node': hex_data[16:18],
                'payload': hex_data[18:],
                'checksum': fcs.hex(),
                'timestamp': datetime.datetime.now()
            }
            
        except Exception as e:
            if debug:
                cprint(f"    [DEBUG] Parse error: {e}", Colors.FAIL)
            return None

    def build_frame(self, home_id: str, src_node: str, dst_node: str, 
               payload: bytes, secure: bool = False) -> bytes:
        """
        Build a Z-Wave frame for transmission
        
        Returns:
            Complete frame bytes (WITHOUT preamble - hardware adds it)
        """
        # Preamble (used for checksum calculation but not transmitted)
        d_init = b"\x00\x0E"
        
        # Parse inputs
        d_homeID = bytes.fromhex(home_id)
        d_SrcNode = bytes.fromhex(src_node)
        d_header = b"\x41\x01"
        d_DstNode = bytes.fromhex(dst_node)
        
        # Calculate length
        d_length = len(payload) + len(d_homeID) + len(d_header) + 4
        d_length = bytes([d_length])
        
        # Build frame for checksum (includes preamble)
        checksum_data = d_init + d_homeID + d_SrcNode + d_header + d_length + d_DstNode + payload
        
        # Calculate checksum starting from index 2 (skip preamble in calculation)
        checksum = 0xff
        for i in range(2, len(checksum_data)):
            byte_val = checksum_data[i] if isinstance(checksum_data[i], int) else ord(checksum_data[i])
            checksum ^= byte_val
        d_checksum = bytes([checksum])
        
        # Return frame WITHOUT preamble (RFxmit will add it)
        return d_homeID + d_SrcNode + d_header + d_length + d_DstNode + payload + d_checksum
    
    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        """Calculate Z-Wave checksum (XOR of all bytes)"""
        checksum = 0xff
        for byte_val in data:
            if isinstance(byte_val, int):
                checksum ^= byte_val
            else:
                checksum ^= ord(byte_val)
        return checksum

    def is_ack_frame(self, frame: Dict) -> bool:
        """Check if frame is an ACK"""
        return frame.get('length') == '0a'
