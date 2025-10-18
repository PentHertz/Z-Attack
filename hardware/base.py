"""
Abstract base class for hardware devices
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

from abc import ABC, abstractmethod
from typing import Optional

class HardwareDevice(ABC):
    """Abstract base class for Z-Wave hardware devices"""
    
    def __init__(self):
        self.is_initialized = False
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the hardware device"""
        pass
    
    @abstractmethod
    def receive(self, timeout: int = 10) -> Optional[bytes]:
        """
        Receive data from the device
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Received bytes or None
        """
        pass
    
    @abstractmethod
    def transmit(self, data: bytes) -> bool:
        """
        Transmit data through the device
        
        Args:
            data: Data to transmit
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def cleanup(self):
        """Clean up and close the device"""
        pass
    
    @abstractmethod
    def get_device_type(self) -> str:
        """Get device type identifier"""
        pass

