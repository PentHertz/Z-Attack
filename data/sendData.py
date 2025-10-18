"""
Data section
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

CmdClassToSend = {
"D - BATTERY_GET":"\x80\x02\x00\x86",
"D - SWITCH_ALL_GET":"\x27\x02\x00\x00",
"D - SENSOR_BINARY_GET":"\x30\x02\x00\x00",
"D - BASIC_GET":"\x20\x02\x00\x00",
"D - ALARM_GET":"\x71\x04\x00\x00",
"D - CONFIGURATION_GET":"\x70\x05\x01\x00",
"D - MANUFACTURER_GET":"\x72\x04\x00\x86",
"D - FUNC_QUERY":"\x01\x02\x00\x00",
"D - VERSION_GET":"\x86\x11\x00\x00",
"D - POWERLEVEL_GET":"\x73\x02\x00\x86",
"D - THERMOSTAT_MODE_GET (untested)":"\x40\x02\x00\x00",
"D - PROTECTION_GET":"\x75\x02\x00\x00",
"A - SWITCH_BINARY_SET_ON":"\x25\x01\xff\x00",
"A - SWITCH_BINARY_SET_OFF":"\x25\x01\x00\x00",
"A - SWITCH_BINARY_REPORT_ON":"\x25\x03\xff\x00",
"A - SWITCH_BINARY_REPORT_OFF":"\x25\x03\x00\x00",
"A - SECURITY_SchemeGet":"\x98\x04\x00\x00",
"A - SECURITY_NonceGet":"\x98\x40\x00\x00",
"A - SCENE_ACTIVATION_SET(BTN-1 zwave.me KEYFOB)":"\x2b\x01\x0b\xff", 
"A - SCENE_ACTIVATION_SET(BTN-2 zwave.me KEYFOB)":"\x2b\x01\x15\xff", 
"A - SCENE_ACTIVATION_SET(BTN-3 zwave.me KEYFOB)":"\x2b\x01\x1f\xff", 
"A - SCENE_ACTIVATION_SET(BTN-4 zwave.me KEYFOB)":"\x2b\x01\x29\xff", 
"A - SCENE_ACTIVATION_SET(BTN-1 AEON KEYFOB)":"\x2b\x01\x01\xff", 
"A - SCENE_ACTIVATION_SET(BTN-2 AEON KEYFOB)":"\x2b\x01\x03\xff", 
"A - SCENE_ACTIVATION_SET(BTN-3 AEON KEYFOB)":"\x2b\x01\x05\xff", 
"A - SCENE_ACTIVATION_SET(BTN-4 AEON KEYFOB)":"\x2b\x01\x07\xff",
}