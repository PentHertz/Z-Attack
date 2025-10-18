"""
GUI utility functions
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

import datetime
from typing import List, Dict, Optional
from PIL import Image
import OpenGL.GL as gl
from config import cprint, Colors

class LogManager:
    """Manages different log types"""
    
    def __init__(self, max_entries: int = 1000):
        self.reception_log: List[str] = []
        self.send_log: List[str] = []
        self.nonce_log: List[str] = []
        self.max_entries = max_entries
        self.captured_nonces: Dict[str, str] = {}
    
    def add_reception(self, entry: str):
        """Add entry to reception log"""
        self.reception_log.insert(0, entry)
        if len(self.reception_log) > self.max_entries:
            self.reception_log = self.reception_log[:self.max_entries]
    
    def add_send(self, entry: str, is_sent: bool = True):
        """Add entry to send/response log"""
        timestamp = str(datetime.datetime.now())
        prefix = "[SENT]    " if is_sent else "[RESPONSE]"
        full_entry = f"{timestamp} {prefix} {entry}"
        self.send_log.insert(0, full_entry)
        if len(self.send_log) > 500:
            self.send_log = self.send_log[:500]
    
    def add_nonce(self, home_id: str, node_id: str, nonce: str):
        """Add captured nonce to log"""
        timestamp = str(datetime.datetime.now())
        key = f"{home_id}-{node_id}"
        self.captured_nonces[key] = nonce
        entry = f"{timestamp} | HomeID:{home_id} Node:{node_id} Nonce:{nonce}"
        self.nonce_log.insert(0, entry)
        if len(self.nonce_log) > 200:
            self.nonce_log = self.nonce_log[:200]
        cprint(f"[NONCE CAPTURED] HomeID:{home_id} Node:{node_id} Nonce:{nonce}", 
               Colors.PURPLE, bold=True)
    
    def clear_nonces(self):
        """Clear all captured nonces"""
        self.captured_nonces.clear()
        self.nonce_log.clear()
    
    def export_nonces(self, filename: str = "output/captured_nonces.txt"):
        """Export nonces to file"""
        try:
            import os
            os.makedirs("output", exist_ok=True)
            with open(filename, "w") as f:
                f.write("Captured Nonces Log\n")
                f.write("="*80 + "\n\n")
                for entry in reversed(self.nonce_log):
                    f.write(entry + "\n")
            return True
        except Exception as e:
            cprint(f"Error exporting nonces: {e}", Colors.FAIL, bold=True)
            return False


def load_texture(path: str) -> tuple:
    """
    Load an image and create an OpenGL texture
    
    Returns:
        (texture_id, width, height) or (None, 0, 0) on failure
    """
    try:
        image = Image.open(path)
        
        # Convert to RGBA
        image = image.convert("RGBA")
        
        # Get image data
        width, height = image.size
        
        # For images with transparency, we need to handle the RGB channels properly
        # Convert to numpy array for processing
        import numpy as np
        img_array = np.array(image)
        
        # If the image has mostly transparent pixels with white text,
        # we need to ensure RGB channels have the correct data
        # Check if RGB channels are all zeros (which would appear black)
        rgb_sum = np.sum(img_array[:, :, :3])
        
        if rgb_sum == 0:
            # Image has all black RGB channels, copy alpha to RGB for white appearance
            cprint(f"[Texture] Image has black RGB channels, converting for visibility", Colors.WARNING)
            for i in range(3):  # R, G, B channels
                img_array[:, :, i] = img_array[:, :, 3]  # Copy alpha to RGB
        
        # Convert back to PIL Image
        image = Image.fromarray(img_array, 'RGBA')
        image_data = image.tobytes()
        
        texture = gl.glGenTextures(1)
        gl.glBindTexture(gl.GL_TEXTURE_2D, texture)
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MIN_FILTER, gl.GL_LINEAR)
        gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MAG_FILTER, gl.GL_LINEAR)
        gl.glTexImage2D(gl.GL_TEXTURE_2D, 0, gl.GL_RGBA, width, height, 0, 
                       gl.GL_RGBA, gl.GL_UNSIGNED_BYTE, image_data)
        
        return texture, width, height
    except Exception as e:
        cprint(f"Failed to load texture {path}: {e}", Colors.WARNING)
        import traceback
        traceback.print_exc()
        return None, 0, 0


class CSVExporter:
    """Export data to CSV files"""
    
    @staticmethod
    def export_log(entries: List[str], filename: str = "output/result.txt"):
        """Export log entries to file"""
        try:
            import os
            os.makedirs("output", exist_ok=True)
            with open(filename, "w") as f:
                f.write("Z-Attack Log Export\n")
                f.write("="*100 + "\n\n")
                for entry in reversed(entries):
                    f.write(entry + "\n")
                    f.write("-"*100 + "\n")
            return True
        except Exception as e:
            cprint(f"Error exporting log: {e}", Colors.FAIL, bold=True)
            return False
