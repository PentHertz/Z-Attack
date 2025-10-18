"""
RfCat hardware implementation
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
from .base import HardwareDevice
from config import cprint, Colors, RFCAT_FREQ, RFCAT_SYNC_WORD, RFCAT_DEVIATN
from config import RFCAT_CHAN_SPC, RFCAT_CHAN_BW, RFCAT_DRATE, RFCAT_PKTLEN

try:
    from rflib import RfCat, MOD_2FSK, SYNCM_CARRIER_15_of_16
    from rflib import ChipconUsbTimeoutException
    RFCAT_AVAILABLE = True
except ImportError:
    RFCAT_AVAILABLE = False
    cprint("[ERROR] RfCat library not available", Colors.FAIL, bold=True)

class RfCatDevice(HardwareDevice):
    """RfCat USB dongle implementation"""
    
    def __init__(self):
        super().__init__()
        self.device = None
    
    def initialize(self) -> bool:
        """Initialize RfCat device"""
        if not RFCAT_AVAILABLE:
            cprint("[RfCat] Library not available", Colors.FAIL)
            return False
        
        try:
            cprint("[RfCat] Initializing device...", Colors.OKBLUE, bold=True)
            self.device = RfCat(0, debug=False)
            self.device.setFreq(RFCAT_FREQ)
            self.device.setMdmModulation(MOD_2FSK)
            self.device.setMdmSyncWord(RFCAT_SYNC_WORD)
            self.device.setMdmDeviatn(RFCAT_DEVIATN)
            self.device.setMdmChanSpc(RFCAT_CHAN_SPC)
            self.device.setMdmChanBW(RFCAT_CHAN_BW)
            self.device.setMdmDRate(RFCAT_DRATE)
            self.device.makePktFLEN(RFCAT_PKTLEN)
            self.device.setEnableMdmManchester(False)
            self.device.setMdmSyncMode(SYNCM_CARRIER_15_of_16)
            
            self.is_initialized = True
            cprint("[RfCat] Device initialized successfully", Colors.OKGREEN, bold=True)
            return True
            
        except Exception as e:
            cprint(f"[RfCat] Initialization failed: {e}", Colors.FAIL, bold=True)
            return False
    
    def receive(self, timeout: int = 10) -> Optional[bytes]:
        """Receive data from RfCat"""
        if not self.is_initialized or not self.device:
            return None
        
        try:
            data = self.device.RFrecv(timeout)
            if data and len(data) > 0:
                return self._invert_bytes(data[0])
            return None
        except ChipconUsbTimeoutException:
            return None
        except Exception:
            return None
    
    def transmit(self, data: bytes) -> bool:
        """Transmit data through RfCat"""
        if not self.is_initialized or not self.device:
            return False
        
        try:
            self.device.RFxmit(self._invert_bytes(data))
            return True
        except Exception as e:
            cprint(f"[RfCat] Transmit failed: {e}", Colors.FAIL)
            return False
    
    def cleanup(self):
        """Clean up RfCat device"""
        if self.device:
            try:
                cprint("[RfCat] Cleaning up device...", Colors.WARNING)
                self.device.setModeIDLE()
                cprint("[RfCat] Device cleaned up", Colors.OKGREEN)
            except Exception as e:
                cprint(f"[RfCat] Cleanup error: {e}", Colors.FAIL)
        self.is_initialized = False
    
    def get_device_type(self) -> str:
        return "RfCat"
    
    @staticmethod
    def _invert_bytes(data: bytes) -> bytes:
        """Invert all bytes (XOR with 0xFF)"""
        return bytes([b ^ 0xFF for b in data])
