"""
Serial port hardware implementation
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

import serial
from typing import Optional
from .base import HardwareDevice
from config import cprint, Colors, SERIAL_BAUDRATE

class SerialDevice(HardwareDevice):
    """Serial port implementation for TI Dev Kit"""
    
    def __init__(self, listen_port: str, send_port: str):
        super().__init__()
        self.listen_port = listen_port
        self.send_port = send_port
        self.listen_serial = None
        self.send_serial = None
    
    def initialize(self) -> bool:
        """Initialize serial ports"""
        try:
            cprint(f"[Serial] Opening listen port: {self.listen_port}", Colors.OKBLUE)
            self.listen_serial = serial.Serial(
                port=self.listen_port,
                baudrate=SERIAL_BAUDRATE,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0
            )
            
            self.is_initialized = True
            cprint("[Serial] Device initialized successfully", Colors.OKGREEN, bold=True)
            return True
            
        except Exception as e:
            cprint(f"[Serial] Initialization failed: {e}", Colors.FAIL, bold=True)
            return False
    
    def receive(self, timeout: int = 10) -> Optional[bytes]:
        """Receive data from serial port"""
        if not self.is_initialized or not self.listen_serial:
            return None
        
        try:
            bytes_to_read = self.listen_serial.inWaiting()
            if bytes_to_read > 2:
                data = self.listen_serial.read(bytes_to_read)
                return data[2:] if len(data) > 2 else data
            return None
        except Exception:
            return None
    
    def transmit(self, data: bytes) -> bool:
        """Transmit data through serial port"""
        if not self.is_initialized:
            return False
        
        try:
            # Open send port temporarily
            send_serial = serial.Serial(
                port=self.send_port,
                baudrate=SERIAL_BAUDRATE,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1
            )
            send_serial.write(data)
            send_serial.close()
            return True
        except Exception as e:
            cprint(f"[Serial] Transmit failed: {e}", Colors.FAIL)
            return False
    
    def cleanup(self):
        """Clean up serial ports"""
        if self.listen_serial and self.listen_serial.is_open:
            try:
                cprint("[Serial] Closing listen port...", Colors.WARNING)
                self.listen_serial.close()
                cprint("[Serial] Serial port closed", Colors.OKGREEN)
            except Exception as e:
                cprint(f"[Serial] Cleanup error: {e}", Colors.FAIL)
        self.is_initialized = False
    
    def get_device_type(self) -> str:
        return "Serial"
