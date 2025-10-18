"""
Z-Wave network management
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

from typing import Dict, List
from config import cprint, Colors

class NetworkManager:
    """Manages Z-Wave network topology and devices"""
    
    def __init__(self):
        self.networks: Dict[str, List[List]] = {}
    
    def add_node(self, home_id: str, node_id: str, device_info: str = ""):
        """Add or update a node in the network"""
        if home_id not in self.networks:
            self.networks[home_id] = [[node_id, device_info]]
            cprint(f"[Network] New network discovered: {home_id}", Colors.HEADER, bold=True)
        else:
            # Check if node already exists
            exists = False
            for i, node in enumerate(self.networks[home_id]):
                if node[0] == node_id:
                    exists = True
                    if device_info:
                        self.networks[home_id][i][1] = device_info
                    break
            
            if not exists:
                self.networks[home_id].append([node_id, device_info])
                cprint(f"[Network] New node discovered: {home_id}:{node_id}", Colors.OKGREEN)
    
    def update_device_info(self, home_id: str, node_id: str, info: str):
        """Update device information for a node"""
        if home_id in self.networks:
            for node in self.networks[home_id]:
                if node[0] == node_id:
                    node[1] = info
                    break
    
    def get_networks(self) -> Dict[str, List[List]]:
        """Get all discovered networks"""
        return self.networks
    
    def get_network_nodes(self, home_id: str) -> List[List]:
        """Get all nodes in a network"""
        return self.networks.get(home_id, [])
    
    def clear(self):
        """Clear all networks"""
        self.networks.clear()
