"""
Configuration settings for Z-Attack
"""

# ANSI Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    ORANGE = '\033[33m'

# RfCat configuration
RFCAT_FREQ = 868399841
RFCAT_MODULATION = None  # Will be set from rflib
RFCAT_SYNC_WORD = 0xaa0f
RFCAT_DEVIATN = 20629.883
RFCAT_CHAN_SPC = 199951.172
RFCAT_CHAN_BW = 101562.5
RFCAT_DRATE = 39970.4
RFCAT_PKTLEN = 48

# Serial configuration
SERIAL_BAUDRATE = 115000

# Default encryption key
DEFAULT_KEY = "0102030405060708090A0B0C0D0E0F10"

# GUI configuration
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 800
LOGO_PATH = "images/zattack.png"

# Output configuration
OUTPUT_DIR = "output"
DISCOVERY_DIR = "discovery"

def cprint(text, color=Colors.ENDC, bold=False):
    """Colored print function"""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{text}{Colors.ENDC}")
