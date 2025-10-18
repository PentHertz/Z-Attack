"""
S2 Security module for Z-Attack
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

try:
    from s2.s2_manager import s2_manager
    from s2.s2_crypto import S2SecurityManager
    S2_AVAILABLE = True
    print("[S2] S2 Security support loaded successfully")
except ImportError as e:
    S2_AVAILABLE = False
    print(f"[S2] Warning: S2 support not available - {e}")
    print("[S2] Install: pip install cryptography pycryptodomex")

__all__ = ['s2_manager', 'S2SecurityManager', 'S2_AVAILABLE']
