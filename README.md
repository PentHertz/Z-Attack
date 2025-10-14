# Z-Attack-ng

**Z-Wave Packet Interception and Injection Tool**

Original tool by [Advens](https://www.advens.fr) (2015)  
Reloaded and enhanced by [Penthertz](https://penthertz.com) (2025)

---

## Overview

Z-Attack is a powerful security research tool for intercepting and injecting Z-Wave packets. This reloaded version features a modern Python 3 implementation with an interactive ImGui-based graphical interface.

**Version 1.0** - Major rewrite with enhanced features

### Key Features

- 🎯 Real-time Z-Wave packet interception and analysis
- 💉 Packet injection capabilities
- 🗺️ Interactive network topology visualization
- 🔐 Nonce capture and management system
- 📊 Advanced logging and analysis
- 🖥️ Modern ImGui graphical interface
- 🔧 Support for RfCat and Texas Instruments development kits
- ⚡ **Z-Wave Plus support** with enhanced command classes
- 🔒 **S2 Security decryption** (FULL SUPPORT with DSK)
- 🔐 **S0 Security decryption** (legacy support)

---

## Z-Wave Plus & Security Support

### ✅ Fully Supported Features

- **Z-Wave Plus Detection**: Automatically identifies Z-Wave Plus devices
- **S2 (Security 2) Full Decryption**: 
  - ✅ Complete ECDH key exchange capture
  - ✅ AES-CCM decryption with authentication
  - ✅ All three security classes (Unauthenticated, Authenticated, Access Control)
  - ✅ Requires DSK (Device Specific Key) from device label
  - ✅ Perfect Forward Secrecy support
  - ✅ SPAN replay protection
- **S0 (Security 0) Full Support**: 
  - ✅ Complete encryption/decryption
  - ✅ Nonce management
  - ✅ AES-128 OFB mode
- **Enhanced Command Classes**: 60+ command classes including:
  - Security 2 (S2) - Detection and analysis
  - Central Scene - Button/scene events
  - Notification/Alarm - Advanced event detection
  - Color Control - RGB/RGBW lighting
  - Door Lock - Smart lock control
  - Barrier Operator - Garage doors/gates
  - Sensor Multilevel - Environmental sensors
  - Multi-channel - Multi-endpoint devices
  - And many more...

### ⚠️ Security Requirements

- **S0 (Security 0)**: ✅ Full support - Can decrypt and inject
  - Requires network key (default or captured)
  - AES-128 encryption
  
- **S2 (Security 2)**: ✅ **FULL DECRYPTION SUPPORT**
  - **Requires DSK** (Device Specific Key from device label)
  - Must capture complete KEX (Key Exchange) during pairing
  - ECDH Curve25519 key exchange
  - AES-CCM authenticated encryption
  - See [S2_DECRYPTION_GUIDE.md](S2_DECRYPTION_GUIDE.md) for detailed instructions

### 📡 Compatible Networks

- Z-Wave (Classic)
- Z-Wave Plus (500 series)
- Z-Wave Plus V2 (700 series) - Limited to S0 security
- Works best with S0-secured or unsecured networks

---

## Installation

### Prerequisites

This tool is compatible with:
- **RfCat** (requires rflib)
- **Texas Instruments development KIT** (with UART bridge)

### Quick Install

1. **Clone the repository:**
```bash
git clone https://github.com/penthertz/z-attack.git
cd z-attack
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install Graphviz (for static network graph export):**

**Debian/Ubuntu:**
```bash
apt-get install graphviz
```

**macOS:**
```bash
brew install graphviz
```

**Windows:**
Download from [https://graphviz.org/download/](https://graphviz.org/download/)

4. **Install RfCat (if using RfCat device):**
```bash
# Follow installation instructions at:
# https://github.com/atlas0fd00m/rfcat
```

---

## Quick Start - S2 Decryption

**Want to decrypt S2 encrypted Z-Wave Plus traffic? Here's how:**

1. **Get the DSK** (Device Specific Key) from your device label/QR code

2. **Start Z-Attack:**
   ```bash
   python3 zattack-ImGUI.py
   ```

3. **Add DSK:** Menu → Add S2 DSK → Enter Node ID and DSK

4. **Pair the device** (Z-Attack captures key exchange automatically)

5. **Done!** All S2 messages now decrypt automatically

---

## Usage

### Command Line Options

```bash
python3 zattack-ImGUI.py [OPTIONS]
```

**Options:**
- `-h` - Display help message
- `-d` - Enable debug mode
- `-csv` - Enable CSV output logging
- `-1` - Use RfCat device (default)
- `-2` - Use TI RF KIT
- `-lcom COM1` - Listening port for TI RF KIT
- `-scom COM2` - Sending port for TI RF KIT

### Examples

**Using RfCat (default):**
```bash
python3 zattack-ImGUI.py
```

**Using RfCat with debug mode:**
```bash
python3 zattack-ImGUI.py -d
```

**Using Texas Instruments RF Kit:**
```bash
python3 zattack-ImGUI.py -2 -lcom /dev/ttyUSB0 -scom /dev/ttyUSB1
```

---

## Features

### Interactive GUI
- Real-time packet reception log
- Send/response log with color coding
- Network topology visualization
- Easy-to-use packet injection interface

### Network Discovery
- Automatic HomeID detection
- Interactive visual network map
- Node identification and tracking
- Export topology to static images

### Security Testing
- Frame interception and analysis
- Nonce capture for encrypted communications (S0 and S2 beta)
- Custom packet crafting and injection
- Support for secure (S0/S2) and unsecure frames
- **Full S2 decryption with DSK**
- S0 backward compatibility

### Logging
- Timestamped packet logs
- CSV export functionality
- Nonce capture history (S0 and S2)
- S2 session management
- Right-click to copy functionality

---

## GUI Overview

### Main Window
- **Reception Log**: Real-time display of intercepted packets
- **Send/Response Log**: Track sent frames and responses
- **Network Info**: View discovered HomeIDs and network topology

### Menu Options
- **Send Frame (Advanced)**: Craft custom Z-Wave packets
- **Send Frame (Easy)**: Quick access to common commands
- **Define AES Key**: Set network key for decryption
- **Captured Nonces**: View and export captured nonces
- **S2 Security Manager**: Manage S2 sessions and keys
- **Add S2 DSK**: Configure device-specific keys for S2 decryption
- **Network Map**: Interactive topology visualization

---

## Requirements

See `requirements.txt` for full Python dependencies:
- Python 3.8+
- PyImGui
- PyOpenGL
- Pillow (PIL)
- pycryptodome (S0 encryption)
- pycryptodomex (S2 encryption)
- cryptography (S2 ECDH)
- pyserial
- pydot
- glfw
- rflib (for RfCat support)

---

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for full details.

---

## Credits

**Original Author:** Advens Security Research Team (2015)  
Website: [www.advens.fr](https://www.advens.fr)

**Reloaded By:** Penthertz (2025)  
Website: [penthertz.com](https://penthertz.com)

---

## Changelog

### Version 1.0 (2025)
- ✨ Complete Python 3 port
- 🎨 New ImGui-based graphical interface
- 🗺️ Interactive network visualization
- 🔐 Enhanced nonce capture system
- 🔒 **Beta S2 (Security 2) decryption support**
- 📡 More Z-Wave Plus command classes
- 🔑 ECDH key exchange capture
- 🛡️ AES-CCM authenticated encryption

### Version 0.1 (2015)
- 🎉 Initial release by Advens
- Basic packet interception
- Injection capabilities
- RfCat and TI Kit support

---

## Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Visit [penthertz.com](https://penthertz.com)