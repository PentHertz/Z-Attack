import serial
import binascii
import pydot
import datetime
import re
from Crypto.Cipher import AES
from Crypto import Random
import sys
from xml.dom.minidom import parse
import xml.dom.minidom
import xml.etree.ElementTree as ET
from xml.dom import minidom
import struct
from serial import *
import imgui
import glfw
from imgui.integrations.glfw import GlfwRenderer
from PIL import Image
import OpenGL.GL as gl
import signal
import atexit

try:
	from rflib import *
except ImportError:
	print("Error : rflib not installed, Rfcat will not work\n")

# import external files
import zwClasses
import sendData

# Import S2 support
try:
	from s2_manager import s2_manager
	from s2_crypto import S2SecurityManager
	S2_AVAILABLE = True
	print("[S2] S2 Security support loaded successfully")
except ImportError as e:
	S2_AVAILABLE = False
	print(f"[S2] Warning: S2 support not available - {e}")
	print("[S2] Install: pip install cryptography pycryptodomex")

# ANSI Color codes for terminal output
class Colors:
	HEADER = '\033[95m'      # Magenta
	OKBLUE = '\033[94m'      # Blue
	OKCYAN = '\033[96m'      # Cyan
	OKGREEN = '\033[92m'     # Green
	WARNING = '\033[93m'     # Yellow
	FAIL = '\033[91m'        # Red
	ENDC = '\033[0m'         # Reset
	BOLD = '\033[1m'         # Bold
	UNDERLINE = '\033[4m'    # Underline
	PURPLE = '\033[35m'      # Purple
	ORANGE = '\033[33m'      # Orange

def cprint(text, color=Colors.ENDC, bold=False):
	"""Colored print function"""
	prefix = Colors.BOLD if bold else ""
	print(f"{prefix}{color}{text}{Colors.ENDC}")

debug = 0
nonce = ""
nonce_other = "000"
frame_nb = 0
key = "0102030405060708090A0B0C0D0E0F10"
Zwave_dic = dict()
is_running = True

# GUI state variables
log_entries = []
send_log_entries = []  # New log for sent frames and responses
nonce_log_entries = []  # Log for captured nonces
captured_nonces = {}  # Dictionary to store nonces: {HomeID-NodeID: nonce}
homeID_input = ""
dstNode_input = ""
srcNode_input = ""
zclass_input = ""
nonce_input = ""
secure_frame = False
selected_homeID = -1
selected_src = -1
selected_dst = -1
selected_cc = -1
key_input = "0102030405060708090A0B0C0D0E0F10"
show_send_window = False
show_easy_window = False
show_key_window = False
show_discovery_window = False
show_about_window = False
show_nonce_window = False
show_s2_window = False
show_s2_dsk_window = False
logo_texture = None
window_impl = None
s2_dsk_input = ""
s2_node_input = ""

def cleanup():
	"""Clean up resources before exit"""
	global d, serialListen, deviceData, window_impl
	
	cprint("\n[*] Cleaning up resources...", Colors.WARNING, bold=True)
	
	try:
		# Clean up RfCat device
		if deviceData == 1:
			try:
				if 'd' in globals() and d is not None:
					cprint("[*] Closing RfCat device...", Colors.OKCYAN)
					d.setModeIDLE()  # Set to idle mode
					# Don't call d.cleanup() as it can cause issues
					cprint("[*] RfCat device closed", Colors.OKGREEN)
			except Exception as e:
				cprint(f"[!] Error closing RfCat: {str(e)}", Colors.FAIL)
		
		# Clean up serial connections
		if deviceData == 2:
			try:
				if 'serialListen' in globals() and serialListen is not None:
					if serialListen.is_open:
						cprint("[*] Closing serial port...", Colors.OKCYAN)
						serialListen.close()
						cprint("[*] Serial port closed", Colors.OKGREEN)
			except Exception as e:
				cprint(f"[!] Error closing serial: {str(e)}", Colors.FAIL)
		
		# Clean up ImGui
		try:
			if window_impl is not None:
				cprint("[*] Shutting down ImGui...", Colors.OKCYAN)
				window_impl.shutdown()
				cprint("[*] ImGui shut down", Colors.OKGREEN)
		except Exception as e:
			cprint(f"[!] Error shutting down ImGui: {str(e)}", Colors.FAIL)
		
		# Clean up GLFW
		try:
			cprint("[*] Terminating GLFW...", Colors.OKCYAN)
			glfw.terminate()
			cprint("[*] GLFW terminated", Colors.OKGREEN)
		except Exception as e:
			cprint(f"[!] Error terminating GLFW: {str(e)}", Colors.FAIL)
		
	except Exception as e:
		cprint(f"[!] Error during cleanup: {str(e)}", Colors.FAIL)
	
	cprint("[*] Cleanup complete. Goodbye!", Colors.OKGREEN, bold=True)

def signal_handler(sig, frame):
	"""Handle Ctrl+C gracefully"""
	global is_running
	cprint("\n[*] Interrupt received, shutting down...", Colors.WARNING, bold=True)
	is_running = False
	cleanup()
	sys.exit(0)

def load_texture(path):
	"""Load an image and create an OpenGL texture"""
	try:
		image = Image.open(path)
		image = image.convert("RGBA")
		width, height = image.size
		image_data = image.tobytes()
		
		texture = gl.glGenTextures(1)
		gl.glBindTexture(gl.GL_TEXTURE_2D, texture)
		gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MIN_FILTER, gl.GL_LINEAR)
		gl.glTexParameteri(gl.GL_TEXTURE_2D, gl.GL_TEXTURE_MAG_FILTER, gl.GL_LINEAR)
		gl.glTexImage2D(gl.GL_TEXTURE_2D, 0, gl.GL_RGBA, width, height, 0, gl.GL_RGBA, gl.GL_UNSIGNED_BYTE, image_data)
		
		return texture, width, height
	except:
		return None, 0, 0

def ByteToHex(byteStr):
	if isinstance(byteStr, str):
		return ''.join(["%02X" % ord(x) for x in byteStr]).strip()
	else:
		return ''.join(["%02X" % x for x in byteStr]).strip()

def checksum(data):
	b = 255
	for i in range(2, len(data)):
		if isinstance(data[i], int):
			b ^= data[i]
		else:
			b ^= data[i]
	cprint(f"	-> Checksum : {format(b, '02x')}", Colors.OKCYAN)
	return bytes([b])

def sendingMode():
	global homeID_input, dstNode_input, srcNode_input, zclass_input, nonce_input, secure_frame
	
	if deviceData == 2:
		cprint("[*] Opening serial port", Colors.OKBLUE, bold=True)
		try:
			serialSend = serial.Serial(port=scom, baudrate=115000, bytesize=serial.EIGHTBITS,
									   parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=1)
		except:
			cprint(f"Error while sending data to {scom}", Colors.FAIL, bold=True)
			return

	cprint("[*] Writing in progress", Colors.OKGREEN, bold=True)
	cprint(f"[*] Sending data to network : {homeID_input}", Colors.HEADER, bold=True)
	cprint(f"	-> DstNode : {dstNode_input}", Colors.OKCYAN)
	cprint(f"	-> SrcNode : {srcNode_input}", Colors.OKCYAN)

	# Header (Preambule + Start of Frame Delimiter)
	d_init = b"\x00\x0E"

	# homeID 4 bytes
	try:
		d_homeID = bytes.fromhex(homeID_input)
	except ValueError as e:
		cprint(f"Error: Invalid HomeID hex value: {homeID_input}", Colors.FAIL, bold=True)
		return
	
	# srcNode 1 byte
	try:
		d_SrcNode = bytes.fromhex(srcNode_input)
	except ValueError as e:
		cprint(f"Error: Invalid SrcNode hex value: {srcNode_input}", Colors.FAIL, bold=True)
		return
	
	d_header = b"\x41\x01"
	
	# dstNode 1 byte
	try:
		d_DstNode = bytes.fromhex(dstNode_input)
	except ValueError as e:
		cprint(f"Error: Invalid DstNode hex value: {dstNode_input}", Colors.FAIL, bold=True)
		return

	d_payload = zclass_input
	cprint(f"	-> Payload : {d_payload}", Colors.OKCYAN)
	
	# Convert payload to bytes
	try:
		d_payload = bytes.fromhex(d_payload)
	except ValueError as e:
		cprint(f"Error: Invalid payload hex value: {zclass_input}", Colors.FAIL, bold=True)
		return

	if secure_frame:
		cprint("[*] Sending secure frame", Colors.WARNING, bold=True)
		d_payload_encrypted = generateEncryptedPayload(d_SrcNode, d_DstNode, d_payload)
		cprint(f"	-> Full Encoded Payload : {d_payload_encrypted.hex()}", Colors.PURPLE)

		d_lenght = len(d_payload_encrypted) + len(d_homeID) + len(d_header) + 4
		d_lenght = bytes([d_lenght])
		cprint(f"	-> Length : {d_lenght.hex()}", Colors.OKCYAN)

		d_checksum = checksum(d_init + d_homeID + d_SrcNode + d_header + d_lenght + d_DstNode + d_payload_encrypted)
		if deviceData == 2:
			serialSend.write(d_init + d_homeID + d_SrcNode + d_header + d_lenght + d_DstNode + d_payload_encrypted + d_checksum)
			serialSend.close()
			# Log the sent frame
			add_send_log_entry(f"SECURE - HomeID:{homeID_input} Src:{srcNode_input} Dst:{dstNode_input} Payload:{zclass_input}", is_sent=True)
		else:
			data = d_homeID + d_SrcNode + d_header + d_lenght + d_DstNode + d_payload_encrypted + d_checksum
			cprint(f"	-> DATA : {data.hex()}", Colors.HEADER)
			d.RFxmit(invert(data))
			# Log the sent frame
			add_send_log_entry(f"SECURE - HomeID:{homeID_input} Src:{srcNode_input} Dst:{dstNode_input} Payload:{zclass_input}", is_sent=True)
		cprint("[*] Done", Colors.OKGREEN, bold=True)
	else:
		cprint("[*] Sending unsecure frame", Colors.WARNING, bold=True)
		d_lenght = len(d_payload) + len(d_homeID) + len(d_header) + 4
		d_lenght = bytes([d_lenght])
		cprint(f"	-> Length : {d_lenght.hex()}", Colors.OKCYAN)

		# Checksum
		d_checksum = checksum(d_init + d_homeID + d_SrcNode + d_header + d_lenght + d_DstNode + d_payload)

		if deviceData == 2:
			serialSend.write(d_init + d_homeID + d_SrcNode + d_header + d_lenght + d_DstNode + d_payload + d_checksum)
			serialSend.close()
		else:
			data = d_homeID + d_SrcNode + d_header + d_lenght + d_DstNode + d_payload + d_checksum
			cprint(f"	-> DATA : {data.hex()}", Colors.HEADER)
			d.RFxmit(invert(data))
			# Log the sent frame
			add_send_log_entry(f"HomeID:{homeID_input} Src:{srcNode_input} Dst:{dstNode_input} Payload:{zclass_input}", is_sent=True)
		cprint("[*] Done", Colors.OKGREEN, bold=True)

def sendingModeRAW(pPayload):
	# Header (Preambule + Start of Frame Delimiter)
	d_init = b"\x00\x0E"
	d_header = b"\x41\x01"

	if selected_homeID >= 0 and selected_homeID < len(list(Zwave_dic.keys())):
		homeids = list(Zwave_dic.keys())
		d_homeID = bytes.fromhex(homeids[selected_homeID])
	else:
		cprint("No HomeID selected", Colors.FAIL, bold=True)
		return

	d_payload = pPayload

	if deviceData == 2:
		cprint("[*] Opening serial port", Colors.OKBLUE, bold=True)
		try:
			serialSend = serial.Serial(port=scom, baudrate=115000, bytesize=serial.EIGHTBITS,
									   parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=1)
		except:
			cprint(f"Error while sending data to {scom}", Colors.FAIL, bold=True)
			return
	cprint("[*] Writing in progress", Colors.OKGREEN, bold=True)
	cprint(f"[*] Sending data to network : {d_homeID.hex()}", Colors.HEADER, bold=True)
	# Checksum
	d_checksum = checksum(d_init + d_homeID + d_payload)

	if deviceData == 2:
		serialSend.write(d_init + d_homeID + d_payload + d_checksum)
		serialSend.close()
		# Log the sent frame
		add_send_log_entry(f"RAW - HomeID:{d_homeID.hex()} Payload:{pPayload.hex()}", is_sent=True)
	else:
		data = d_homeID + d_payload + d_checksum
		cprint(f"	-> DATA : {data.hex()}", Colors.HEADER)
		d.RFxmit(invert(data))
		# Log the sent frame
		add_send_log_entry(f"RAW - HomeID:{d_homeID.hex()} Payload:{pPayload.hex()}", is_sent=True)
	cprint("[*] Done", Colors.OKGREEN, bold=True)

def generate_encrypt_key(key):
	temp_key = bytes.fromhex(key)
	# Default static key for encryption
	msg = b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
	cipher = AES.new(temp_key, AES.MODE_ECB)
	return cipher.encrypt(msg).hex()

def generate_mac_key(key):
	temp_key = bytes.fromhex(key)
	# Default static key for authentication
	msg = b'\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55'
	cipher = AES.new(temp_key, AES.MODE_ECB)
	return cipher.encrypt(msg).hex()

def generateEncryptedPayload(sNode, dNode, payload_to_encrypt):
	global nonce_input
	# We first need to ask a nonce from the device
	nonce_remote_device = nonce_input

	CCMsgEncap = b"\x98\x81"
	sequence = b"\x81"
	nonce = "aaaaaaaaaaaaaaaa"
	nonceId = nonce_remote_device[:2]
	cprint(f"	-> nonceId : {nonceId}", Colors.PURPLE)

	iv = nonce + nonce_remote_device

	payload_to_encrypt = b"\x00" + payload_to_encrypt

	payload_to_encrypt = payload_to_encrypt.hex()
	cprint(f"	-> Payload to encrypt : {payload_to_encrypt}", Colors.OKCYAN)
	cprint(f"	-> IV : {iv}", Colors.OKCYAN)
	iv = bytes.fromhex(iv)

	# Padding 16 bytes msg
	padding = ""
	lenght_payload = len(payload_to_encrypt) // 2
	cprint(f"	-> lenght_payload : {lenght_payload}", Colors.OKCYAN)
	padding_lenght = 32 - (lenght_payload * 2)
	for pad in range(0, padding_lenght):
		padding = padding + "0"
	payload_to_encrypt = str(payload_to_encrypt) + padding
	cprint(f"	-> Payload with padding : {payload_to_encrypt}", Colors.OKCYAN)

	payload_to_encrypt = bytes.fromhex(payload_to_encrypt)

	# Generate Encoded Payload
	encrypt_key = bytes.fromhex(generate_encrypt_key(key))
	cprint(f"	-> encrypt_key : {encrypt_key.hex()}", Colors.OKGREEN)
	cipher = AES.new(encrypt_key, AES.MODE_OFB, iv)
	encodedPayload = cipher.encrypt(payload_to_encrypt)
	cprint(f"	-> encodedPayload : {encodedPayload.hex()}", Colors.OKGREEN)

	# Split payload to initial length
	encodedPayload = encodedPayload[:lenght_payload]
	cprint(f"	-> encodedPayload (split) : {encodedPayload.hex()}", Colors.OKGREEN)

	cprint(f"	-> sNode : {sNode.hex()}", Colors.OKCYAN)
	cprint(f"	-> dNode : {dNode.hex()}", Colors.OKCYAN)

	# Generate MAC Payload to encrypt with MAC key
	authentication_RAW = sequence.hex() + sNode.hex() + dNode.hex() + ("%0.2X" % lenght_payload) + encodedPayload.hex()
	cprint(f"	-> MAC Raw : {authentication_RAW}", Colors.PURPLE)

	# Generate MAC key (ECB)
	authentication_key = bytes.fromhex(generate_mac_key(key))
	cprint(f"	-> MAC_key : {authentication_key.hex()}", Colors.PURPLE)

	# Encrypt IV with ECB
	cipher = AES.new(authentication_key, AES.MODE_ECB)
	tempAuth = cipher.encrypt(iv)
	cprint(f"	-> Encoded IV : {tempAuth.hex()}", Colors.PURPLE)

	# Padding 16 bytes msg for MAC
	padding = ""
	lenght_mac = len(authentication_RAW) // 2
	padding_lenght = 32 - (lenght_mac * 2)
	for pad in range(0, padding_lenght):
		padding = padding + "0"
	authentication_RAW = str(authentication_RAW) + padding
	cprint(f"	-> MAC with padding : {authentication_RAW}", Colors.OKCYAN)

	# XOR with encrypted IV
	l1 = int(authentication_RAW, 16)
	l2 = int(tempAuth.hex(), 16)
	xored = format(l1 ^ l2, 'x')
	cprint(f"	-> XOR MAC : {xored}", Colors.WARNING)
	if len(xored) != 32:
		xored = "0" + xored
	cprint(f"	-> XOR MAC (16 bytes) : {xored}", Colors.WARNING)

	# Encrypt MAC ECB
	xored = bytes.fromhex(xored)
	cipher = AES.new(authentication_key, AES.MODE_ECB)
	encodedMAC = cipher.encrypt(xored)
	cprint(f"	-> Encoded MAC : {encodedMAC.hex()}", Colors.OKGREEN)

	# Split MAC to 8 bytes
	encodedMAC = encodedMAC[:8]
	cprint(f"	-> Encoded MAC (split) : {encodedMAC.hex()}", Colors.OKGREEN)

	EncodedFrame = CCMsgEncap + bytes.fromhex(nonce) + encodedPayload + bytes.fromhex(nonceId) + encodedMAC

	return EncodedFrame

def decrypt(payload_enc, nonce_other, nonce_device, payload, lenght_encrypted_payload):
	global key
	result = ""
	if len(key) == 32:
		encrypt_key = generate_encrypt_key(key)
		key_aes = bytes.fromhex(encrypt_key)
		if nonce_device and nonce_other:
			iv = nonce_device + nonce_other
			
			# Padding 16 bytes msg
			padding = ""
			if (lenght_encrypted_payload) > 16 and (lenght_encrypted_payload) < 32:
				if debug:
					cprint("			[2 BLOCKS CIPHER TO DECRYPT] (hex):", Colors.WARNING, bold=True)
				
				payload_enc_block1 = payload_enc[0:32]
				payload_enc_block2 = payload_enc[32:]
				cprint(f"			Block 1: {payload_enc_block1}", Colors.OKCYAN)
				cprint(f"			Block 2: {payload_enc_block2}", Colors.OKCYAN)
				lenght_payload_enc_block2 = len(payload_enc_block2) // 2
				padding_lenght = 32 - (lenght_payload_enc_block2 * 2)
				for pad in range(0, padding_lenght):
					padding = padding + "0"
				payload_enc_block2 = str(payload_enc_block2) + padding

				if debug:
					cprint(f"			[MSG TO DECODE] (hex): {payload_enc}", Colors.PURPLE)
				payload_enc_block1 = bytes.fromhex(payload_enc_block1)
				payload_enc_block2 = bytes.fromhex(payload_enc_block2)

				try:
					iv = bytes.fromhex(iv)
					cprint(f"			[IV] (hex) : {iv.hex()}", Colors.OKGREEN)
					
					cipher = AES.new(key_aes, AES.MODE_OFB, iv)
					result1 = cipher.decrypt(payload_enc_block1).hex()
					result2 = cipher.decrypt(payload_enc_block2).hex()
					result = result1 + result2
					cprint(f"			[DECODED] Payload (hex): {result}", Colors.OKGREEN, bold=True)
				except:
					cprint("Error during decrypting", Colors.FAIL, bold=True)
			else:
				padding_lenght = 32 - (lenght_encrypted_payload * 2)
				for pad in range(0, padding_lenght):
					padding = padding + "0"
				payload_enc = str(payload_enc) + padding
				if debug:
					cprint(f"			[MSG TO DECODE] (hex): {payload_enc}", Colors.PURPLE)
				payload_enc = bytes.fromhex(payload_enc)
				
				try:
					iv = bytes.fromhex(iv)
					cprint(f"			[IV] (hex) : {iv.hex()}", Colors.OKGREEN)
					cipher = AES.new(key_aes, AES.MODE_OFB, iv)
					result = cipher.decrypt(payload_enc).hex()
					cprint(f"			[DECODED] Payload (hex): {result}", Colors.OKGREEN, bold=True)
				except:
					cprint("Error during decrypting", Colors.FAIL, bold=True)
	else:
		cprint("			[DEBUG] Error with network key", Colors.FAIL, bold=True)
		result = ""
	return result[2:]

def zclassFinder(payload, HomeID, SrcNode):
	# Payload analysis
	global nonce_other
	ZwClass = payload[0:2]

	param = cc = cmd = mapManufacturer = ""
	
	# ==================== S2 DETECTION AND DECRYPTION ====================
	if ZwClass == "9f":
		cprint(f"		[S2 SECURITY DETECTED] Command Class: Security2", Colors.PURPLE, bold=True)
		CmdClass = payload[2:4]
		
		# Try S2 decryption if available
		if S2_AVAILABLE:
			try:
				decrypted = s2_manager.process_s2_frame(payload, HomeID, SrcNode, "01")  # Assuming controller is 01
				
				if decrypted:
					# Successfully decrypted - process the decrypted payload
					cprint(f"		[S2] ✓✓✓ DECRYPTED PAYLOAD ✓✓✓", Colors.OKGREEN, bold=True)
					payload = decrypted
					# Recursively process the decrypted payload
					return zclassFinder(decrypted, HomeID, SrcNode)
			except Exception as e:
				cprint(f"		[S2] Decryption attempt failed: {e}", Colors.WARNING)
		
		# If not decrypted, show S2 command info
		if CmdClass in zwClasses.ZwaveClass[ZwClass].keys():
			cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]
			cprint(f"		Command= {cmd}", Colors.WARNING, bold=True)
			
			if cmd == "Security2Cmd_MessageEncap":
				cprint("		[!] S2 ENCRYPTED MESSAGE - Cannot decrypt (S2 not supported)", Colors.FAIL, bold=True)
				cprint("		[i] This is Z-Wave Plus S2 encryption (stronger than S0)", Colors.WARNING)
				
				# Try to extract some basic info
				try:
					sequence = payload[4:6]
					cprint(f"		Sequence Number: {sequence}", Colors.OKCYAN)
					param = "Security2  |  " + cmd + " (ENCRYPTED - S2 not supported)"
				except:
					param = "Security2  |  " + cmd + " (ENCRYPTED)"
				
			elif cmd == "Security2Cmd_KexReport":
				cprint("		[S2] Key Exchange Report", Colors.PURPLE, bold=True)
				try:
					# Parse KEX report
					if len(payload) > 6:
						request_csa = payload[4:6]
						schemes = payload[6:8]
						curves = payload[8:10]
						keys = payload[10:12]
						cprint(f"		Request CSA: {request_csa}", Colors.OKCYAN)
						cprint(f"		KEX Schemes: {schemes}", Colors.OKCYAN)
						cprint(f"		KEX Curves: {curves}", Colors.OKCYAN)
						cprint(f"		Requested Keys: {keys}", Colors.OKCYAN)
						param = "Security2  |  KEX Report (S2 Key Exchange)"
				except:
					param = "Security2  |  " + cmd
					
			elif cmd == "Security2Cmd_NonceReport":
				cprint("		[S2] Nonce Report", Colors.PURPLE, bold=True)
				try:
					if len(payload) > 20:
						s2_nonce = payload[4:20]
						cprint(f"		S2 Nonce: {s2_nonce}", Colors.OKGREEN)
						cprint("		[!] Note: S2 nonces use different encryption than S0", Colors.WARNING)
						param = "Security2  |  Nonce Report | Nonce=" + s2_nonce
				except:
					param = "Security2  |  " + cmd
					
			elif cmd == "Security2Cmd_PublicKeyReport":
				cprint("		[S2] Public Key Exchange (ECDH)", Colors.PURPLE, bold=True)
				param = "Security2  |  Public Key Report (ECDH Key Exchange)"
				
			elif cmd == "Security2Cmd_NetworkKeyGet":
				cprint("		[S2] Network Key Request", Colors.WARNING, bold=True)
				param = "Security2  |  Network Key Get"
				
			elif cmd == "Security2Cmd_NetworkKeyVerify":
				cprint("		[S2] Network Key Verification", Colors.OKGREEN, bold=True)
				param = "Security2  |  Network Key Verify"
				
			else:
				param = "Security2  |  " + cmd
		else:
			param = "Security2  |  UNKNOWN_COMMAND"
		
		return param
	
	# ==================== REGULAR COMMAND CLASS PROCESSING ====================
	if ZwClass in zwClasses.ZwaveClass.keys():
		cprint(f"		CommandClass= {zwClasses.ZwaveClass[ZwClass]['name']}", Colors.HEADER)
		CmdClass = payload[2:4]
		cc = zwClasses.ZwaveClass[ZwClass]['name']
		if CmdClass in zwClasses.ZwaveClass[ZwClass].keys():
			cprint(f"		Command= {zwClasses.ZwaveClass[ZwClass][CmdClass]}", Colors.OKBLUE)
			cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]

			param = cc + "  |  " + cmd + "("

			if zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_MessageEncap":
				lenght_encrypted_payload = (len(payload) // 2) - 8 - 2 - 8
				if debug:
					cprint(f"		[DEBUG][lenght_encrypted_payload] : {lenght_encrypted_payload} bytes", Colors.OKCYAN)
				nonce_device = payload[4:20]
				payload_enc = payload[20:(lenght_encrypted_payload) * 2 + 20]
				auth_enc = payload[-16:]
				if debug:
					cprint(f"		[DEBUG][Nonce]= {nonce_device}	[Encrypted payload]= {payload_enc}	[Authentication MAC]= {auth_enc}", Colors.PURPLE)
				if nonce_other:
					payloadDecoded = decrypt(payload_enc, nonce_other, nonce_device, payload, lenght_encrypted_payload)
					payload = payloadDecoded
					try:
						if debug:
							cprint(f"		[DEBUG] payloadDecoded {payloadDecoded}", Colors.OKGREEN)
						ZwClass = payloadDecoded[0:2]
						CmdClass = payloadDecoded[2:4]
						cc = zwClasses.ZwaveClass[ZwClass]['name']
						cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]
						param += cc + "|" + cmd + "("
					except:
						cprint("		[Error during decrypting data]", Colors.FAIL, bold=True)
						return
				else:
					cprint("		[DEBUG] Unable to decrypt - no device nonce", Colors.WARNING)

			if zwClasses.ZwaveClass[ZwClass][CmdClass] == "ManufacturerSpecificCmd_Report":
				manufacturer = payload[4:8]
				product = payload[8:12]
				
				# Parse XML file to find manufacturer
				try:
					xmldoc = minidom.parse('manufacturer_specific.xml')
					manufacturers_xml = xmldoc.getElementsByTagName('Manufacturer')
					for s in manufacturers_xml:
						if manufacturer == s.attributes['id'].value:
							manufacturer = s.attributes['name'].value
							products_xml = s.getElementsByTagName('Product')
							for product_xml in products_xml:
								if product == product_xml.attributes['type'].value:
									product = product_xml.attributes['name'].value
				except:
					pass
				cprint(f"		Manufacturer= {manufacturer}		Product= {product}", Colors.OKGREEN)
				param += "Manufacturer=" + manufacturer + "|Product=" + product
				mapManufacturer = "Manufacturer=" + manufacturer + "|Product=" + product

				for i in range(len(Zwave_dic[HomeID])):
					if SrcNode in Zwave_dic[HomeID][i]:
						Zwave_dic[HomeID][i] = [SrcNode, manufacturer + " | " + product]

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_NonceReport":
				nonce_other = payload[4:20]
				if debug:
					cprint(f"		[DEBUG][GET Nonce] : {nonce_other}", Colors.OKGREEN, bold=True)
				param += nonce_other
				# Capture the nonce
				add_nonce_log_entry(HomeID, SrcNode, nonce_other)

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "VersionCmd_Report":
				lib = payload[4:6]
				protocol_hex = payload[6:10]
				application_hex = payload[10:14]

				lib = str(int(lib, 16))
				if lib in zwClasses.LIBRARY.keys():
					lib = zwClasses.LIBRARY[lib]
					
				protocol = str(int(protocol_hex[:2], 16)) + "." + str(int(protocol_hex[2:4], 16))
				application = str(int(application_hex[:2], 16)) + "." + str(int(application_hex[2:4], 16))
				
				cprint(f"		library= {lib}	protocol= {protocol}	application= {application}", Colors.OKCYAN)
				param += "library=" + lib + "|protocol=" + protocol + "|application=" + application

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "BatteryCmd_Report":
				param1 = payload[4:6]
				if param1 == "ff":
					cprint("		Param[1]= (Battery = 0)", Colors.FAIL)
					param += "Battery = 0"
				else:
					cprint(f"		Param[1]= (Battery = {str(int(param1, 16))})", Colors.OKGREEN)
					param += "Battery = " + str(int(param1, 16))

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] in ["SwitchBinaryCmd_Set", "SwitchBinaryCmd_Report", "BasicCmd_Report", "BasicCmd_Set", "SensorBinaryCmd_Report", "SwitchMultilevelCmd_Report"]:
				param1 = payload[4:6]
				if param1 == "ff":
					cprint("		Param[1]= On", Colors.OKGREEN, bold=True)
					param += "On"
				if param1 == "00":
					cprint("		Param[1]= Off", Colors.FAIL, bold=True)
					param += "Off"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_NetworkKeySet":
				temp_key = payload[4:36]
				cprint(f"			[NETWORK KEY] (hex) : {temp_key}", Colors.WARNING, bold=True)
				param += temp_key

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "MeterCmd_Report":
				val = payload[12:16]
				param += str(int(val, 16) // 1000) + " Watts"

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SensorAlarmCmd_Report":
				param1 = payload[4:6]
				alarm_types = {
					"00": "General Purpose Alarm",
					"01": "Smoke Alarm",
					"02": "CO Alarm",
					"03": "CO2 Alarm",
					"04": "Heat Alarm",
					"05": "Water Leak Alarm"
				}
				if param1 in alarm_types:
					cprint(f"		Param[1]= {alarm_types[param1]}", Colors.WARNING, bold=True)
					param += alarm_types[param1]

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "PowerlevelCmd_Report":
				param1 = payload[4:6]
				power_levels = {
					"00": "Normal", "01": "-1dB", "02": "-2dB", "03": "-3dB",
					"04": "-4dB", "05": "-5dB", "06": "-6dB", "07": "-7dB",
					"08": "-8dB", "09": "-9dB"
				}
				if param1 in power_levels:
					cprint(f"		Param[1]= {power_levels[param1]}", Colors.OKCYAN)
					param += power_levels[param1]

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ThermostatModeCmd_Report":
				param1 = payload[4:6]
				thermostat_modes = {
					"00": "Off", "01": "Heat", "02": "Cool", "03": "Auto",
					"04": "Auxiliary/Emergency Heat", "05": "Resume",
					"06": "Fan Only", "07": "Furnace", "08": "Dry Air",
					"09": "Moist Air", "10": "Auto Changeover",
					"11": "Energy Save Heat", "12": "Energy Save Cool", "13": "AWAY"
				}
				if param1 in thermostat_modes:
					cprint(f"		Param[1]= {thermostat_modes[param1]}", Colors.OKCYAN)
					param += thermostat_modes[param1]

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ProtectionCmd_Report":
				param1 = payload[4:6]
				protection_modes = {
					"00": "Unprotected",
					"01": "Protection by sequence",
					"02": "No operation possible"
				}
				if param1 in protection_modes:
					cprint(f"		Param[1]= {protection_modes[param1]}", Colors.OKCYAN)
					param += protection_modes[param1]

			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchAllCmd_Report":
				param1 = payload[4:6]
				switch_modes = {
					"00": "Excluded from the all on/all off functionality",
					"01": "Excluded from the all on functionality but not all off",
					"02": "Excluded from the all off functionality but not all on",
					"ff": "Included in the all on/all off functionality"
				}
				if param1 in switch_modes:
					cprint(f"		Param[1]= {switch_modes[param1]}", Colors.OKCYAN)
					param += switch_modes[param1]
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ZwaveplusInfoCmd_Report":
				cprint("		[Z-WAVE PLUS DEVICE DETECTED]", Colors.PURPLE, bold=True)
				try:
					zwave_plus_version = payload[4:6]
					role_type = payload[6:8]
					node_type = payload[8:10]
					installer_icon = payload[10:14]
					user_icon = payload[14:18]
					
					role_types = {
						"00": "Central Static Controller",
						"01": "Sub Static Controller",
						"02": "Portable Controller",
						"03": "Portable Reporting Controller",
						"04": "Portable Slave",
						"05": "Always On Slave",
						"06": "Sleeping Reporting Slave",
						"07": "Sleeping Listening Slave"
					}
					
					role_name = role_types.get(role_type, f"Unknown ({role_type})")
					cprint(f"		Z-Wave Plus Version: {zwave_plus_version}", Colors.OKCYAN)
					cprint(f"		Role Type: {role_name}", Colors.OKGREEN)
					cprint(f"		Node Type: {node_type}", Colors.OKCYAN)
					cprint(f"		Installer Icon: {installer_icon}", Colors.OKCYAN)
					cprint(f"		User Icon: {user_icon}", Colors.OKCYAN)
					param += f"Z-Wave Plus v{int(zwave_plus_version, 16)}|Role={role_name}"
				except:
					param += "Z-Wave Plus Info"
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "NotificationCmd_Report":
				cprint("		[NOTIFICATION/ALARM]", Colors.WARNING, bold=True)
				try:
					notification_type = payload[10:12]
					notification_event = payload[12:14]
					
					notification_types = {
						"01": "Smoke Alarm", "02": "CO Alarm", "03": "CO2 Alarm",
						"04": "Heat Alarm", "05": "Water Alarm", "06": "Access Control",
						"07": "Home Security", "08": "Power Management", "09": "System",
						"0a": "Emergency", "0b": "Clock", "0c": "Appliance"
					}
					
					notif_name = notification_types.get(notification_type, f"Type {notification_type}")
					cprint(f"		Notification Type: {notif_name}", Colors.WARNING)
					cprint(f"		Event: {notification_event}", Colors.WARNING)
					
					# Specific event details for common types
					if notification_type == "07":  # Home Security
						events = {
							"00": "Idle", "01": "Intrusion", "02": "Intrusion Unknown Location",
							"03": "Tamper Cover Removed", "05": "Glass Breakage",
							"06": "Motion Detection", "07": "Motion Detection Unknown Location",
							"08": "Tamper Invalid Code"
						}
						event_name = events.get(notification_event, "Unknown Event")
						cprint(f"		Home Security Event: {event_name}", Colors.FAIL, bold=True)
						param += f"Home Security|{event_name}"
					elif notification_type == "06":  # Access Control
						events = {
							"01": "Manual Lock", "02": "Manual Unlock", "03": "RF Lock",
							"04": "RF Unlock", "05": "Keypad Lock", "06": "Keypad Unlock",
							"0b": "Lock Jammed", "0c": "All Codes Deleted"
						}
						event_name = events.get(notification_event, "Unknown Event")
						cprint(f"		Access Control Event: {event_name}", Colors.OKGREEN)
						param += f"Access Control|{event_name}"
					else:
						param += f"{notif_name}|Event={notification_event}"
				except:
					param += "Notification/Alarm"
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "CentralSceneCmd_Notification":
				cprint("		[CENTRAL SCENE] Button/Scene Event", Colors.PURPLE, bold=True)
				try:
					sequence = payload[4:6]
					key_attributes = payload[6:8]
					scene_number = payload[8:10]
					
					key_attrs = {
						"00": "Key Pressed 1x",
						"01": "Key Released",
						"02": "Key Held Down",
						"03": "Key Pressed 2x",
						"04": "Key Pressed 3x",
						"05": "Key Pressed 4x",
						"06": "Key Pressed 5x"
					}
					
					attr_name = key_attrs.get(key_attributes, f"Unknown ({key_attributes})")
					cprint(f"		Scene Number: {int(scene_number, 16)}", Colors.OKGREEN)
					cprint(f"		Key Attribute: {attr_name}", Colors.OKGREEN)
					param += f"Scene {int(scene_number, 16)}|{attr_name}"
				except:
					param += "Central Scene Notification"
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ColorControlCmd_Report":
				cprint("		[COLOR CONTROL] RGB/RGBW Light", Colors.PURPLE)
				try:
					color_component = payload[4:6]
					color_value = payload[6:8]
					
					components = {
						"00": "Warm White", "01": "Cold White", "02": "Red",
						"03": "Green", "04": "Blue", "05": "Amber", "06": "Cyan",
						"07": "Purple", "08": "Indexed Color"
					}
					
					comp_name = components.get(color_component, f"Component {color_component}")
					value = int(color_value, 16)
					cprint(f"		Color Component: {comp_name}", Colors.OKCYAN)
					cprint(f"		Value: {value}", Colors.OKCYAN)
					param += f"{comp_name}={value}"
				except:
					param += "Color Control Report"
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "DoorLockCmd_Report":
				cprint("		[DOOR LOCK] Status Report", Colors.OKGREEN, bold=True)
				try:
					lock_mode = payload[4:6]
					
					lock_modes = {
						"00": "Door Unsecured",
						"01": "Door Unsecured with timeout",
						"10": "Door Unsecured for inside Door Handles",
						"11": "Door Unsecured for inside Door Handles with timeout",
						"20": "Door Unsecured for outside Door Handles",
						"21": "Door Unsecured for outside Door Handles with timeout",
						"ff": "Door Secured"
					}
					
					mode_name = lock_modes.get(lock_mode, f"Unknown ({lock_mode})")
					color = Colors.FAIL if lock_mode == "ff" else Colors.OKGREEN
					cprint(f"		Lock Status: {mode_name}", color, bold=True)
					param += mode_name
				except:
					param += "Door Lock Report"
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "BarrierOperatorCmd_Report":
				cprint("		[BARRIER OPERATOR] Garage Door/Gate", Colors.OKBLUE, bold=True)
				try:
					state = payload[4:6]
					
					states = {
						"00": "Closed",
						"fc": "Closing",
						"fd": "Stopped",
						"fe": "Opening",
						"ff": "Open"
					}
					
					state_name = states.get(state, f"Unknown ({state})")
					cprint(f"		Barrier State: {state_name}", Colors.OKGREEN)
					param += state_name
				except:
					param += "Barrier Operator Report"
			
			elif zwClasses.ZwaveClass[ZwClass][CmdClass] in ["SensorMultilevelCmd_Report"]:
				cprint("		[SENSOR MULTILEVEL] Environmental Sensor", Colors.OKCYAN)
				try:
					sensor_type = payload[4:6]
					precision_scale_size = payload[6:8]
					
					sensor_types = {
						"01": "Temperature", "02": "General Purpose", "03": "Luminance",
						"04": "Power", "05": "Humidity", "06": "Velocity", "07": "Direction",
						"08": "Atmospheric Pressure", "09": "Barometric Pressure",
						"0a": "Solar Radiation", "0b": "Dew Point", "0c": "Rain Rate",
						"0d": "Tide Level", "0e": "Weight", "0f": "Voltage",
						"10": "Current", "11": "CO2 Level", "12": "Air Flow",
						"13": "Tank Capacity", "14": "Distance", "15": "Angle Position",
						"16": "Rotation", "17": "Water Temperature", "18": "Soil Temperature",
						"19": "Seismic Intensity", "1a": "Seismic Magnitude",
						"1b": "Ultraviolet", "1c": "Electrical Resistivity",
						"1d": "Electrical Conductivity", "1e": "Loudness", "1f": "Moisture",
						"20": "Frequency", "21": "Time", "22": "Target Temperature"
					}
					
					sensor_name = sensor_types.get(sensor_type, f"Unknown ({sensor_type})")
					
					# Parse precision, scale, size
					pss_int = int(precision_scale_size, 16)
					precision = (pss_int >> 5) & 0x07
					scale = (pss_int >> 3) & 0x03
					size = pss_int & 0x07
					
					# Extract value
					value_hex = payload[8:8+(size*2)]
					if value_hex:
						value = int(value_hex, 16)
						# Apply precision
						if precision > 0:
							value = value / (10 ** precision)
						
						cprint(f"		Sensor Type: {sensor_name}", Colors.OKGREEN)
						cprint(f"		Value: {value}", Colors.OKGREEN)
						param += f"{sensor_name}={value}"
					else:
						param += sensor_name
				except:
					param += "Sensor Multilevel Report"

			param += ")"
	else:
		param = "UNKNOWN"
	return param

def invert(data):
	if isinstance(data, str):
		data = data.encode()
	return bytes([b ^ 0xFF for b in data])

def calculateChecksum(data):
	checksum = 0xff
	for byte in data:
		if isinstance(byte, int):
			checksum ^= byte
		else:
			checksum ^= ord(byte)
	return checksum

def add_log_entry(entry):
	"""Add a log entry to the display"""
	global log_entries
	log_entries.insert(0, entry)
	if len(log_entries) > 1000:  # Keep only last 1000 entries
		log_entries = log_entries[:1000]

def add_send_log_entry(entry, is_sent=True):
	"""Add a send/response log entry to the display"""
	global send_log_entries
	timestamp = str(datetime.datetime.now())
	prefix = "[SENT]    " if is_sent else "[RESPONSE]"
	full_entry = f"{timestamp} {prefix} {entry}"
	send_log_entries.insert(0, full_entry)
	if len(send_log_entries) > 500:  # Keep only last 500 entries
		send_log_entries = send_log_entries[:500]

def add_nonce_log_entry(homeid, nodeid, nonce):
	"""Add a captured nonce to the log and dictionary"""
	global nonce_log_entries, captured_nonces
	timestamp = str(datetime.datetime.now())
	key = f"{homeid}-{nodeid}"
	captured_nonces[key] = nonce
	entry = f"{timestamp} | HomeID:{homeid} Node:{nodeid} Nonce:{nonce}"
	nonce_log_entries.insert(0, entry)
	if len(nonce_log_entries) > 200:
		nonce_log_entries = nonce_log_entries[:200]
	cprint(f"[NONCE CAPTURED] HomeID:{homeid} Node:{nodeid} Nonce:{nonce}", Colors.PURPLE, bold=True)

def listeningMode():
	global frame_nb
	payload = ""
	res = b""

	# TI Dev KIT
	if deviceData == 2:
		bytesToRead = serialListen.inWaiting()
		res = serialListen.read(bytesToRead)
		if len(res) > 2:
			res = res[2:]
	# Retrieve data from Rfcat
	else:
		try:
			res = d.RFrecv(10)[0]
			res = invert(res)
		except ChipconUsbTimeoutException:
			pass
		except:
			pass

	if res:
		print("")
		cprint(str(datetime.datetime.now()), Colors.HEADER, bold=True)
		if debug:
			cprint(f"	[DEBUG Serial data received] {res.hex()}", Colors.OKCYAN)

		# Check if several frames in one
		frames = re.split(b"\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\xf0", res)

		if debug:
			cprint(f"	[Number of frames] {str(len(frames))}", Colors.OKBLUE)

		for frame in frames:
			res = frame
			print("")
			if debug:
				cprint(f'	[DEBUG Frame] {res.hex()}', Colors.PURPLE)
			
			try:
				if len(res) > 7:
					lenght = res[7] if isinstance(res[7], int) else ord(res[7])
					res = res[0:lenght]
					# Check CRC and remove noise
					fcs = res[-1:] if isinstance(res[-1], bytes) else bytes([res[-1]])
					res = res[:-1]
					calculatedchecksumFrame = calculateChecksum(res)
					fcs_int = fcs[0] if isinstance(fcs[0], int) else ord(fcs[0])
					if calculatedchecksumFrame != fcs_int:
						cprint(f"	Checksum: {fcs.hex()} (Incorrect)", Colors.FAIL)
						res = b""
			except:
				cprint("	[Error during FCS calc : Dropped] ", Colors.FAIL)
				cprint(f"	[Frame] {str(res)}", Colors.FAIL)

			if res:
				res = res.hex()

				# PATCH REMOVE UNUSEFUL DATA
				res = re.sub(r'00[0-1][0-1][0-1][a-f0-9]', '', res)
				res = re.sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]00000', '', res)
				res = re.sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]', '', res)

				# Decode Zwave frame
				HomeID = res[0:8]
				SrcNode = res[8:10]
				FrameControl = res[10:14]
				Length = res[14:16]
				DstNode = res[16:18]
				payload = res[18:]

				if Length == "0a":
					cprint(f"	ACK response from {SrcNode} to {DstNode}", Colors.OKGREEN, bold=True)
					# Log the ACK response in both logs
					add_send_log_entry(f"ACK from {SrcNode} to {DstNode}", is_sent=False)
					# Add to reception log
					frame_nb = frame_nb + 1
					ack_entry = f"{frame_nb}  |  {datetime.datetime.now()}  |  {HomeID}  |  {SrcNode}  |  {DstNode}  |  ACK Response"
					add_log_entry(ack_entry)
					
					# Write to file if output enabled
					if fOutput:
						try:
							fOutputCSV = open("output/result.txt", "a")
							fOutputCSV.write("\n" + str(frame_nb) + "  |  " + str(datetime.datetime.now()) + "  |  " + HomeID + "  |  " + SrcNode + "  |  " + DstNode + "  |  ACK Response")
							fOutputCSV.write("\n-----------------------------------------------------------------------------------------------------------------------------------------------------")
							fOutputCSV.close()
						except:
							pass
				
				if len(payload) < 128 and len(payload) > 0:
					cprint("	Zwave frame:", Colors.HEADER, bold=True)
					cprint(f"		HomeID= {HomeID}", Colors.OKCYAN)
					cprint(f"		SrcNode= {SrcNode}", Colors.OKCYAN)
					cprint(f"		DstNode= {DstNode}", Colors.OKCYAN)
					cprint(f"		Checksum= {fcs.hex()}", Colors.OKCYAN)

					if DstNode == "ff":
						cprint("		[*] Broadcast frame", Colors.WARNING, bold=True)
					
					# Generate a list of HomeID and Nodes
					if HomeID in Zwave_dic.keys():
						if SrcNode:
							tt = 0
							for i in range(len(Zwave_dic[HomeID])):
								if SrcNode in Zwave_dic[HomeID][i]:
									tt = 1
							if tt == 0:
								list_SrcNode = [SrcNode, '']
								Zwave_dic[HomeID].append(list_SrcNode)
						if DstNode and DstNode != "ff":
							tt = 0
							for i in range(len(Zwave_dic[HomeID])):
								if DstNode in Zwave_dic[HomeID][i]:
									tt = 1
							if tt == 0:
								list_DstNode = [DstNode, '']
								Zwave_dic[HomeID].append(list_DstNode)
					else:
						if SrcNode:
							list_SrcNode = [[SrcNode, '']]
							Zwave_dic[HomeID] = list_SrcNode
						if DstNode and DstNode != "ff":
							list_DstNode = [DstNode, '']
							Zwave_dic[HomeID].append(list_DstNode)

					decodedPayload = zclassFinder(payload, HomeID, SrcNode)
					if decodedPayload:
						frame_nb = frame_nb + 1

						# Add to GUI log
						log_entry = f"{frame_nb}  |  {datetime.datetime.now()}  |  {HomeID}  |  {SrcNode}  |  {DstNode}  |  {decodedPayload}"
						add_log_entry(log_entry)
						
						# Write output to file (CSV)
						if fOutput:
							try:
								fOutputCSV = open("output/result.txt", "a")
								fOutputCSV.write("\n" + str(frame_nb) + "  |  " + str(datetime.datetime.now()) + "  |  " + HomeID + "  |  " + SrcNode + "  |  " + DstNode + "  |  " + decodedPayload + "  |  " + payload)
								fOutputCSV.write("\n-----------------------------------------------------------------------------------------------------------------------------------------------------")
								fOutputCSV.close()
							except:
								pass
						
						if debug:
							cprint(f"	[DEBUG] Payload= {payload}", Colors.PURPLE)

def scanZwaveNetwork():
	sendingModeRAW(b"\x01\x41\x01\x0e\xff\x72\x04\x00\x86")

def render_gui():
	global show_send_window, show_easy_window, show_key_window, show_discovery_window, show_about_window, show_nonce_window
	global show_s2_window, show_s2_dsk_window
	global homeID_input, dstNode_input, srcNode_input, zclass_input, nonce_input, secure_frame
	global selected_homeID, selected_src, selected_dst, selected_cc, key_input, key
	global logo_texture, logo_width, logo_height
	global s2_dsk_input, s2_node_input

	imgui.new_frame()

	# Main window
	imgui.set_next_window_position(0, 0)
	imgui.set_next_window_size(1400, 800)
	imgui.begin("Z-Attack - Z-Wave Packet Interception and Injection Tool", flags=imgui.WINDOW_NO_RESIZE | imgui.WINDOW_NO_MOVE | imgui.WINDOW_MENU_BAR)

	# Menu bar
	if imgui.begin_menu_bar():
		if imgui.begin_menu("Menu"):
			if imgui.menu_item("Send Frame (Advanced)")[0]:
				show_send_window = True
			if imgui.menu_item("Send Frame (Easy)")[0]:
				show_easy_window = True
			if imgui.menu_item("Define AES Key")[0]:
				show_key_window = True
			if imgui.menu_item("Captured Nonces")[0]:
				show_nonce_window = True
			if S2_AVAILABLE:
				if imgui.menu_item("S2 Security Manager")[0]:
					show_s2_window = True
				if imgui.menu_item("Add S2 DSK")[0]:
					show_s2_dsk_window = True
			if imgui.menu_item("Network Map")[0]:
				show_discovery_window = True
			if imgui.menu_item("Quit")[0]:
				cleanup()
				sys.exit(0)
			imgui.end_menu()
		
		if imgui.begin_menu("Help"):
			if imgui.menu_item("About")[0]:
				show_about_window = True
			imgui.end_menu()
		
		imgui.end_menu_bar()

	# Create two columns - left for logs, right for network info
	imgui.columns(2, "main_columns")
	imgui.set_column_width(0, 900)
	
	# Left column - Reception and Send logs
	imgui.begin_child("Reception", width=0, height=350, border=True)
	imgui.text("Reception Log:")
	imgui.same_line()
	imgui.text_colored("(Right-click to copy)", 0.5, 0.5, 0.5)
	imgui.separator()
	
	imgui.begin_child("LogScroll", width=0, height=0, border=False)
	for entry in log_entries:
		imgui.selectable(entry, False)
		if imgui.is_item_hovered() and imgui.is_mouse_clicked(1):  # Right click
			imgui.set_clipboard_text(entry)
	imgui.end_child()
	
	imgui.end_child()

	# Send/Response log (bottom of left column)
	imgui.begin_child("SendLog", width=0, height=380, border=True)
	imgui.text("Send/Response Log:")
	imgui.same_line()
	imgui.text_colored("(Right-click to copy)", 0.5, 0.5, 0.5)
	imgui.separator()
	
	imgui.begin_child("SendLogScroll", width=0, height=0, border=False)
	for entry in send_log_entries:
		if "[SENT]" in entry:
			imgui.push_style_color(imgui.COLOR_TEXT, 1.0, 0.647, 0.0)
		else:
			imgui.push_style_color(imgui.COLOR_TEXT, 0.0, 1.0, 1.0)
		imgui.selectable(entry, False)
		if imgui.is_item_hovered() and imgui.is_mouse_clicked(1):  # Right click
			imgui.set_clipboard_text(entry)
		imgui.pop_style_color()
	imgui.end_child()
	
	imgui.end_child()

	# Right column - Logo and Network info (aligned with top)
	imgui.next_column()
	
	imgui.begin_child("RightPanel", width=0, height=0, border=False)
	
	# Logo (if available)
	if logo_texture:
		imgui.image(logo_texture, logo_width, logo_height)
	
	imgui.text("Z-Wave Network Information")
	imgui.text("Home IDs Around You:")
	
	imgui.begin_child("HomeIDList", width=0, height=200, border=True)
	homeids = list(Zwave_dic.keys())
	for i, homeid in enumerate(homeids):
		if imgui.selectable(homeid, selected_homeID == i)[0]:
			selected_homeID = i
	imgui.end_child()
	
	imgui.end_child()
	
	# End columns
	imgui.columns(1)

	imgui.end()

	# Send Frame (Advanced) Window
	if show_send_window:
		imgui.set_next_window_size(1000, 700, imgui.ONCE)
		expanded, show_send_window = imgui.begin("Send Frame (Advanced Mode)", True)
		if expanded:
			# Top section - Input fields
			imgui.text("Emission:")
			imgui.separator()
			
			imgui.columns(2, "input_columns")
			changed, homeID_input = imgui.input_text("HomeID", homeID_input, 256)
			imgui.next_column()
			changed, dstNode_input = imgui.input_text("DstNode", dstNode_input, 256)
			imgui.columns(1)
			
			imgui.columns(2, "input_columns2")
			changed, srcNode_input = imgui.input_text("SrcNode", srcNode_input, 256)
			imgui.next_column()
			changed, zclass_input = imgui.input_text("Zclass", zclass_input, 256)
			imgui.columns(1)
			
			changed, nonce_input = imgui.input_text("Nonce", nonce_input, 256)
			changed, secure_frame = imgui.checkbox("Secure (Nonce required)", secure_frame)
			
			if imgui.button("Send", width=200, height=40):
				sendingMode()
			
			imgui.separator()
			imgui.text("Selection:")
			imgui.separator()
			
			# Bottom section - Selection lists in 4 columns
			imgui.columns(4, "select_columns")
			
			# Column 1: HomeID
			imgui.text("HomeID:")
			imgui.begin_child("HomeIDSelect", width=0, height=200, border=True)
			homeids = list(Zwave_dic.keys())
			for i, homeid in enumerate(homeids):
				if imgui.selectable(homeid, selected_homeID == i)[0]:
					selected_homeID = i
					homeID_input = str(homeid)
					selected_src = -1
					selected_dst = -1
			imgui.end_child()
			
			imgui.next_column()
			
			# Column 2: Source Node
			imgui.text("Source Node:")
			imgui.begin_child("SrcSelect", width=0, height=200, border=True)
			if selected_homeID >= 0 and selected_homeID < len(homeids):
				nodes = Zwave_dic[homeids[selected_homeID]]
				for i, node in enumerate(nodes):
					if imgui.selectable(node[0], selected_src == i)[0]:
						selected_src = i
						srcNode_input = str(node[0])
			imgui.end_child()
			
			imgui.next_column()
			
			# Column 3: Dest Node
			imgui.text("Dest Node:")
			imgui.begin_child("DstSelect", width=0, height=200, border=True)
			if selected_homeID >= 0 and selected_homeID < len(homeids):
				nodes = Zwave_dic[homeids[selected_homeID]]
				for i, node in enumerate(nodes):
					if imgui.selectable(node[0], selected_dst == i)[0]:
						selected_dst = i
						dstNode_input = str(node[0])
			imgui.end_child()
			
			imgui.next_column()
			
			# Column 4: Command Class
			imgui.text("Command Class:")
			imgui.begin_child("CCSelect", width=0, height=200, border=True)
			try:
				cc_list = sorted(sendData.CmdClassToSend.keys())
				for i, cc_name in enumerate(cc_list):
					clicked, _ = imgui.selectable(cc_name, selected_cc == i)
					if clicked:
						selected_cc = i
						cc_value = sendData.CmdClassToSend[cc_name]
						
						# Convert to proper hex string
						temp_value = ""
						if isinstance(cc_value, bytes):
							# Bytes object - convert to hex
							temp_value = cc_value.hex()
						elif isinstance(cc_value, bytearray):
							# Bytearray - convert to hex
							temp_value = bytes(cc_value).hex()
						elif isinstance(cc_value, str):
							# String might contain raw bytes or hex
							# First, try to encode to bytes then to hex
							try:
								# This is a string with raw byte characters like '+\x01\x15ÿ'
								temp_value = cc_value.encode('latin-1').hex()
							except:
								# If that fails, assume it's already hex
								temp_value = ''.join(c for c in cc_value if c in '0123456789abcdefABCDEF')
						else:
							try:
								temp_value = bytes(cc_value).hex()
							except:
								temp_value = str(cc_value)
						
						zclass_input = temp_value
						
			except Exception as e:
				imgui.text(f"Error: {str(e)}")
			imgui.end_child()
			
			imgui.columns(1)
		imgui.end()

	# Send Frame (Easy) Window
	if show_easy_window:
		imgui.set_next_window_size(400, 200, imgui.ONCE)
		expanded, show_easy_window = imgui.begin("Send Frame (Easy Mode)", True)
		if expanded:
			if selected_homeID >= 0:
				if imgui.button("Network Discovery"):
					scanZwaveNetwork()
				if imgui.button("Turn On Lights"):
					sendingModeRAW(b"\x01\x41\x01\x0e\xff\x25\x01\xff\x4c")
				if imgui.button("Turn Off Lights"):
					sendingModeRAW(b"\x01\x41\x01\x0e\xff\x25\x01\x00\x4c")
			else:
				imgui.text("Please select a HomeID first")
		imgui.end()

	# AES Key Window
	if show_key_window:
		imgui.set_next_window_size(500, 150, imgui.ONCE)
		expanded, show_key_window = imgui.begin("AES Encryption", True)
		if expanded:
			imgui.text("Define Network Key to decrypt (default OZW):")
			_, key_input = imgui.input_text("Key", key_input, 256)
			if imgui.button("Define"):
				key = key_input
				cprint(f"[NETWORK KEY CHANGED] (hex): {key}", Colors.OKGREEN, bold=True)
		imgui.end()

	# Network Map Window
	if show_discovery_window:
		imgui.set_next_window_size(1000, 700, imgui.ONCE)
		expanded, show_discovery_window = imgui.begin("Network Discovery - Interactive Map", True)
		if expanded:
			if selected_homeID >= 0 and selected_homeID < len(list(Zwave_dic.keys())):
				homeids = list(Zwave_dic.keys())
				selected_home = homeids[selected_homeID]
				
				imgui.text(f"Network Map for HomeID: {selected_home}")
				imgui.separator()
				
				# Interactive visual map
				imgui.text("Interactive Network Topology:")
				imgui.text_colored("Hover over nodes for details, click to select", 0.7, 0.7, 0.7)
				imgui.separator()
				
				# Create drawing area
				draw_list = imgui.get_window_draw_list()
				canvas_pos = imgui.get_cursor_screen_pos()
				canvas_size = (950, 450)
				
				imgui.begin_child("NetworkCanvas", width=canvas_size[0], height=canvas_size[1], border=True)
				
				# Background
				draw_list.add_rect_filled(
					canvas_pos[0], canvas_pos[1],
					canvas_pos[0] + canvas_size[0], canvas_pos[1] + canvas_size[1],
					imgui.get_color_u32_rgba(0.05, 0.05, 0.05, 1.0)
				)
				
				# Calculate layout
				import math
				nodes_list = Zwave_dic[selected_home]
				num_nodes = len(nodes_list)
				
				# Find controller
				controller_node = None
				other_nodes = []
				for node in nodes_list:
					if str(node[0]) == "01":
						controller_node = node
					else:
						other_nodes.append(node)
				
				# Controller at center
				center_x = canvas_pos[0] + canvas_size[0] // 2
				center_y = canvas_pos[1] + canvas_size[1] // 2
				controller_radius = 50
				node_radius = 35
				
				mouse_pos = imgui.get_mouse_pos()
				is_mouse_in_canvas = (canvas_pos[0] <= mouse_pos[0] <= canvas_pos[0] + canvas_size[0] and
									  canvas_pos[1] <= mouse_pos[1] <= canvas_pos[1] + canvas_size[1])
				
				# Draw controller
				if controller_node:
					# Connection lines to all nodes (draw first so they're behind)
					orbit_radius = 150
					for i, node in enumerate(other_nodes):
						angle = (2 * math.pi * i / len(other_nodes)) - (math.pi / 2)
						node_x = center_x + orbit_radius * math.cos(angle)
						node_y = center_y + orbit_radius * math.sin(angle)
						
						# Animated dashed line
						import time
						dash_offset = int(time.time() * 50) % 20
						for d in range(0, int(math.hypot(node_x - center_x, node_y - center_y)), 20):
							if (d + dash_offset) % 20 < 10:
								t = d / math.hypot(node_x - center_x, node_y - center_y)
								x1 = center_x + t * (node_x - center_x)
								y1 = center_y + t * (node_y - center_y)
								t2 = min(1.0, (d + 10) / math.hypot(node_x - center_x, node_y - center_y))
								x2 = center_x + t2 * (node_x - center_x)
								y2 = center_y + t2 * (node_y - center_y)
								draw_list.add_line(x1, y1, x2, y2, 
												 imgui.get_color_u32_rgba(0.3, 0.6, 1.0, 0.6), 2.0)
					
					# Controller glow effect
					for glow in range(3):
						glow_size = controller_radius + (glow * 5)
						alpha = 0.15 - (glow * 0.04)
						draw_list.add_circle_filled(
							center_x, center_y, glow_size,
							imgui.get_color_u32_rgba(1.0, 0.2, 0.2, alpha), 32
						)
					
					# Controller circle
					draw_list.add_circle_filled(
						center_x, center_y, controller_radius,
						imgui.get_color_u32_rgba(0.8, 0.1, 0.1, 1.0), 32
					)
					draw_list.add_circle(
						center_x, center_y, controller_radius,
						imgui.get_color_u32_rgba(1.0, 0.3, 0.3, 1.0), 32, 3.0
					)
					
					# Controller icon (star shape)
					star_points = 5
					outer_r = controller_radius * 0.4
					inner_r = controller_radius * 0.2
					for i in range(star_points * 2):
						angle = (math.pi * i / star_points) - (math.pi / 2)
						r = outer_r if i % 2 == 0 else inner_r
						x = center_x + r * math.cos(angle)
						y = center_y + r * math.sin(angle)
						next_i = (i + 1) % (star_points * 2)
						next_angle = (math.pi * next_i / star_points) - (math.pi / 2)
						next_r = outer_r if next_i % 2 == 0 else inner_r
						next_x = center_x + next_r * math.cos(next_angle)
						next_y = center_y + next_r * math.sin(next_angle)
						draw_list.add_line(x, y, next_x, next_y,
										 imgui.get_color_u32_rgba(1.0, 1.0, 0.3, 1.0), 2.0)
					
					# Controller text
					text = "CONTROLLER"
					text_size = imgui.calc_text_size(text)
					draw_list.add_text(
						center_x - text_size.x / 2, center_y + controller_radius + 5,
						imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), text
					)
					
					node_id_text = f"Node {controller_node[0]}"
					node_id_size = imgui.calc_text_size(node_id_text)
					draw_list.add_text(
						center_x - node_id_size.x / 2, center_y - 8,
						imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), node_id_text
					)
					
					# Hover effect for controller
					dist = math.hypot(mouse_pos[0] - center_x, mouse_pos[1] - center_y)
					if is_mouse_in_canvas and dist <= controller_radius:
						imgui.set_tooltip(f"HomeID: {selected_home}\nNode: {controller_node[0]}\nType: Z-Wave Controller")
				
				# Draw other nodes in a circle around controller
				orbit_radius = 150
				for i, node in enumerate(other_nodes):
					angle = (2 * math.pi * i / len(other_nodes)) - (math.pi / 2)
					node_x = center_x + orbit_radius * math.cos(angle)
					node_y = center_y + orbit_radius * math.sin(angle)
					
					node_id = str(node[0])
					node_info = str(node[1]) if len(node) > 1 and node[1] else "Unknown Device"
					
					# Check if mouse is over this node
					dist = math.hypot(mouse_pos[0] - node_x, mouse_pos[1] - node_y)
					is_hovered = is_mouse_in_canvas and dist <= node_radius
					
					# Node glow when hovered
					if is_hovered:
						for glow in range(3):
							glow_size = node_radius + (glow * 4)
							alpha = 0.2 - (glow * 0.05)
							draw_list.add_circle_filled(
								node_x, node_y, glow_size,
								imgui.get_color_u32_rgba(0.3, 1.0, 0.3, alpha), 32
							)
					
					# Node circle
					node_color = (0.2, 0.8, 0.2, 1.0) if is_hovered else (0.1, 0.6, 0.1, 1.0)
					draw_list.add_circle_filled(
						node_x, node_y, node_radius,
						imgui.get_color_u32_rgba(*node_color), 32
					)
					draw_list.add_circle(
						node_x, node_y, node_radius,
						imgui.get_color_u32_rgba(0.3, 1.0, 0.3, 1.0), 32, 2.5
					)
					
					# Device icon (simple chip design)
					chip_size = node_radius * 0.5
					draw_list.add_rect_filled(
						node_x - chip_size/2, node_y - chip_size/2,
						node_x + chip_size/2, node_y + chip_size/2,
						imgui.get_color_u32_rgba(0.2, 0.2, 0.2, 1.0)
					)
					# Chip pins
					for pin in range(4):
						pin_offset = chip_size * 0.3
						if pin == 0:  # Top
							draw_list.add_line(node_x, node_y - chip_size/2, node_x, node_y - chip_size/2 - 5,
											 imgui.get_color_u32_rgba(0.7, 0.7, 0.7, 1.0), 2.0)
						elif pin == 1:  # Right
							draw_list.add_line(node_x + chip_size/2, node_y, node_x + chip_size/2 + 5, node_y,
											 imgui.get_color_u32_rgba(0.7, 0.7, 0.7, 1.0), 2.0)
						elif pin == 2:  # Bottom
							draw_list.add_line(node_x, node_y + chip_size/2, node_x, node_y + chip_size/2 + 5,
											 imgui.get_color_u32_rgba(0.7, 0.7, 0.7, 1.0), 2.0)
						elif pin == 3:  # Left
							draw_list.add_line(node_x - chip_size/2, node_y, node_x - chip_size/2 - 5, node_y,
											 imgui.get_color_u32_rgba(0.7, 0.7, 0.7, 1.0), 2.0)
					
					# Node ID
					node_text = f"Node {node_id}"
					text_size = imgui.calc_text_size(node_text)
					draw_list.add_text(
						node_x - text_size.x / 2, node_y + node_radius + 5,
						imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), node_text
					)
					
					# Show tooltip on hover
					if is_hovered:
						tooltip_text = f"Node: {node_id}\nDevice: {node_info}\nHomeID: {selected_home}"
						imgui.set_tooltip(tooltip_text)
				
				# Draw legend
				legend_x = canvas_pos[0] + 10
				legend_y = canvas_pos[1] + 10
				
				# Legend background
				draw_list.add_rect_filled(
					legend_x, legend_y, legend_x + 150, legend_y + 80,
					imgui.get_color_u32_rgba(0.1, 0.1, 0.1, 0.8)
				)
				draw_list.add_rect(
					legend_x, legend_y, legend_x + 150, legend_y + 80,
					imgui.get_color_u32_rgba(0.5, 0.5, 0.5, 1.0), 0.0, 0, 1.5
				)
				
				# Legend items
				draw_list.add_text(legend_x + 5, legend_y + 5,
								 imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Legend:")
				
				# Controller
				draw_list.add_circle_filled(legend_x + 15, legend_y + 30, 8,
										   imgui.get_color_u32_rgba(0.8, 0.1, 0.1, 1.0), 16)
				draw_list.add_text(legend_x + 30, legend_y + 23,
								 imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Controller")
				
				# Device
				draw_list.add_circle_filled(legend_x + 15, legend_y + 55, 8,
										   imgui.get_color_u32_rgba(0.1, 0.6, 0.1, 1.0), 16)
				draw_list.add_text(legend_x + 30, legend_y + 48,
								 imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Device")
				
				# Network stats
				stats_x = canvas_pos[0] + canvas_size[0] - 160
				stats_y = canvas_pos[1] + 10
				draw_list.add_rect_filled(
					stats_x, stats_y, stats_x + 150, stats_y + 60,
					imgui.get_color_u32_rgba(0.1, 0.1, 0.1, 0.8)
				)
				draw_list.add_rect(
					stats_x, stats_y, stats_x + 150, stats_y + 60,
					imgui.get_color_u32_rgba(0.5, 0.5, 0.5, 1.0), 0.0, 0, 1.5
				)
				draw_list.add_text(stats_x + 5, stats_y + 5,
								 imgui.get_color_u32_rgba(1.0, 1.0, 1.0, 1.0), "Network Stats:")
				draw_list.add_text(stats_x + 5, stats_y + 25,
								 imgui.get_color_u32_rgba(0.7, 0.7, 1.0, 1.0), 
								 f"Total Devices: {len(other_nodes)}")
				draw_list.add_text(stats_x + 5, stats_y + 40,
								 imgui.get_color_u32_rgba(0.7, 1.0, 0.7, 1.0), 
								 f"Controllers: {1 if controller_node else 0}")
				
				imgui.end_child()
				
				imgui.separator()
				
				# Export options
				imgui.text("Export Options:")
				if imgui.button("Generate Static Graph Image (Graphviz)", width=300):
					try:
						import os
						if not os.path.exists("discovery"):
							os.makedirs("discovery")
						
						graph = pydot.Dot(graph_type='digraph')
						graph.set_bgcolor('white')
						node_controler = None
						
						for j in range(len(Zwave_dic[selected_home])):
							nodes = Zwave_dic[selected_home][j]
							if str(nodes[0]) == "01":
								node_controler = pydot.Node("HomeID " + selected_home, style="filled", fillcolor="red")
								graph.add_node(node_controler)
						
						if node_controler:
							for j in range(len(Zwave_dic[selected_home])):
								nodes = Zwave_dic[selected_home][j]
								if str(nodes[0]) != "01":
									node_label = "NodeID " + str(nodes[0])
									if len(nodes) > 1 and nodes[1]:
										node_label += "\\n" + str(nodes[1])
									node_x = pydot.Node(node_label, style="filled", fillcolor="lightgreen")
									graph.add_node(node_x)
									graph.add_edge(pydot.Edge(node_controler, node_x))
						
						output_path = "discovery/" + selected_home + "_graph.png"
						graph.write_png(output_path)
						cprint(f"Graph saved to: {output_path}", Colors.OKGREEN, bold=True)
						imgui.text(f"Success! Graph saved to: {output_path}")
					except FileNotFoundError as e:
						error_msg = "Error: Graphviz not found! Please install it"
						imgui.text_colored(error_msg, 1.0, 0.0, 0.0)
						cprint(error_msg, Colors.FAIL, bold=True)
					except Exception as e:
						error_msg = f"Error generating graph: {str(e)}"
						imgui.text_colored(error_msg, 1.0, 0.5, 0.0)
						cprint(error_msg, Colors.WARNING, bold=True)
				
				imgui.same_line()
				imgui.text_colored("(Optional - requires Graphviz)", 0.6, 0.6, 0.6)
				
			else:
				imgui.text("Please select a HomeID first from the main window")
		imgui.end()

	# Captured Nonces Window
	if show_nonce_window:
		imgui.set_next_window_size(800, 500, imgui.ONCE)
		expanded, show_nonce_window = imgui.begin("Captured Nonces", True)
		if expanded:
			imgui.text("Captured Nonces Log:")
			imgui.text_colored("Right-click to copy NONCE VALUE only", 0.5, 0.5, 0.5)
			imgui.separator()
			
			imgui.begin_child("NonceLogScroll", width=0, height=350, border=True)
			for entry in nonce_log_entries:
				imgui.push_style_color(imgui.COLOR_TEXT, 0.8, 0.4, 1.0)  # Purple
				imgui.selectable(entry, False)
				if imgui.is_item_hovered() and imgui.is_mouse_clicked(1):  # Right click
					# Extract just the nonce value from the entry
					# Format: "timestamp | HomeID:xxx Node:xx Nonce:xxxxxxxxxxxxxxxx"
					if "Nonce:" in entry:
						nonce_value = entry.split("Nonce:")[1].strip()
						imgui.set_clipboard_text(nonce_value)
					else:
						imgui.set_clipboard_text(entry)
				imgui.pop_style_color()
			imgui.end_child()
			
			imgui.separator()
			imgui.text(f"Total captured: {len(captured_nonces)} unique nonces")
			
			if imgui.button("Clear All Nonces"):
				captured_nonces.clear()
				nonce_log_entries.clear()
				cprint("[NONCES CLEARED]", Colors.WARNING, bold=True)
			
			imgui.same_line()
			if imgui.button("Export to File"):
				try:
					import os
					if not os.path.exists("output"):
						os.makedirs("output")
					with open("output/captured_nonces.txt", "w") as f:
						f.write("Captured Nonces Log\n")
						f.write("="*80 + "\n\n")
						for entry in reversed(nonce_log_entries):
							f.write(entry + "\n")
					cprint("Nonces exported to output/captured_nonces.txt", Colors.OKGREEN, bold=True)
					imgui.text("Exported to output/captured_nonces.txt")
				except Exception as e:
					cprint(f"Error exporting nonces: {str(e)}", Colors.FAIL, bold=True)
		imgui.end()

	# About Window
	if show_about_window:
		imgui.set_next_window_size(300, 200, imgui.ONCE)
		expanded, show_about_window = imgui.begin("About", True)
		if expanded:
			imgui.text("Z-Attack 1.0")
			imgui.text("Author: Advens")
			imgui.text("Reloaded by: Penthertz")
			imgui.text("Website: penthertz.com")
			imgui.text("")
			imgui.text("Python 3 + ImGui Port")
			if S2_AVAILABLE:
				imgui.text_colored("S2 Support: Enabled", 0.0, 1.0, 0.0)
			else:
				imgui.text_colored("S2 Support: Disabled", 1.0, 0.5, 0.0)
		imgui.end()
	
	# S2 Security Manager Window
	if show_s2_window and S2_AVAILABLE:
		imgui.set_next_window_size(900, 600, imgui.ONCE)
		expanded, show_s2_window = imgui.begin("S2 Security Manager", True)
		if expanded:
			imgui.text_colored("S2 (Security 2) Session Management (alpha testing)", 1.0, 0.8, 0.0)
			imgui.separator()
			
			# Session status
			imgui.text("Active S2 Sessions:")
			imgui.separator()
			
			imgui.begin_child("S2Sessions", width=0, height=200, border=True)
			if s2_manager.sessions:
				for key, session in s2_manager.sessions.items():
					has_dsk = session.dsk is not None
					has_secret = session.shared_secret is not None
					has_keys = len(session.ccm_keys) > 0
					
					status_color = (0.0, 1.0, 0.0) if (has_dsk and has_secret and has_keys) else (1.0, 0.5, 0.0)
					
					imgui.push_style_color(imgui.COLOR_TEXT, *status_color)
					imgui.text(f"Session: {key}")
					imgui.pop_style_color()
					
					imgui.same_line(200)
					imgui.text(f"DSK: {'✓' if has_dsk else '✗'}")
					imgui.same_line(280)
					imgui.text(f"Secret: {'✓' if has_secret else '✗'}")
					imgui.same_line(380)
					imgui.text(f"Keys: {len(session.ccm_keys)}")
					
					if has_dsk and has_secret and has_keys:
						imgui.same_line(450)
						imgui.text_colored("READY TO DECRYPT", 0.0, 1.0, 0.0)
			else:
				imgui.text_colored("No active S2 sessions", 0.7, 0.7, 0.7)
			imgui.end_child()
			
			imgui.separator()
			
			# Captured data
			imgui.columns(3, "s2_data_columns")
			
			# Column 1: Known DSKs
			imgui.text("Known DSKs:")
			imgui.begin_child("DSKList", width=0, height=150, border=True)
			if s2_manager.known_dsks:
				for node_id, dsk in s2_manager.known_dsks.items():
					imgui.text(f"Node {node_id}:")
					imgui.text(f"  {dsk.hex()}")
			else:
				imgui.text_colored("No DSKs configured", 0.7, 0.7, 0.7)
				imgui.text("")
				imgui.text_colored("Use 'Add S2 DSK' menu", 0.5, 0.5, 1.0)
			imgui.end_child()
			
			imgui.next_column()
			
			# Column 2: Public Keys
			imgui.text("Captured Public Keys:")
			imgui.begin_child("PubKeyList", width=0, height=150, border=True)
			if s2_manager.captured_public_keys:
				for key, pubkey in s2_manager.captured_public_keys.items():
					imgui.text(f"{key}:")
					imgui.text(f"  {pubkey.hex()[:32]}...")
			else:
				imgui.text_colored("No public keys captured", 0.7, 0.7, 0.7)
			imgui.end_child()
			
			imgui.next_column()
			
			# Column 3: Nonces
			imgui.text("Captured S2 Nonces:")
			imgui.begin_child("S2NonceList", width=0, height=150, border=True)
			if s2_manager.captured_nonces:
				for key, nonce_data in s2_manager.captured_nonces.items():
					imgui.text(f"{key}:")
					imgui.text(f"  {nonce_data['entropy'][:16]}...")
			else:
				imgui.text_colored("No S2 nonces captured", 0.7, 0.7, 0.7)
			imgui.end_child()
			
			imgui.columns(1)
			
			imgui.separator()
			
			# Actions
			imgui.text("Actions:")
			if imgui.button("List Sessions (Console)", width=200):
				s2_manager.list_sessions()
			
			imgui.same_line()
			if imgui.button("Export Session Data", width=200):
				s2_manager.export_session_data("output/s2_sessions.txt")
			
			imgui.same_line()
			if imgui.button("Clear All Sessions", width=200):
				s2_manager.sessions.clear()
				s2_manager.captured_public_keys.clear()
				s2_manager.captured_nonces.clear()
				cprint("[S2 Manager] All sessions cleared", Colors.WARNING, bold=True)
			
			imgui.separator()
			
			# Instructions
			imgui.text_colored("How to decrypt S2 traffic:", 1.0, 1.0, 0.0)
			imgui.text("1. Add device DSK using 'Add S2 DSK' menu (find on device label)")
			imgui.text("2. Capture full KEX exchange (when device joins network)")
			imgui.text("3. Tool will automatically decrypt subsequent messages")
			imgui.text("4. Check console output for decryption status")
			
		imgui.end()
	
	# S2 DSK Input Window
	if show_s2_dsk_window and S2_AVAILABLE:
		imgui.set_next_window_size(600, 300, imgui.ONCE)
		expanded, show_s2_dsk_window = imgui.begin("Add S2 DSK", True)
		if expanded:
			imgui.text("Add Device Specific Key (DSK) for S2 Decryption")
			imgui.separator()
			
			imgui.text_colored("DSK is printed on device label or QR code", 0.7, 0.7, 0.7)
			imgui.text_colored("Format: 12345-67890-12345-67890-12345-67890-12345-67890", 0.7, 0.7, 0.7)
			imgui.text_colored("Or hex: 0102030405060708090a0b0c0d0e0f10", 0.7, 0.7, 0.7)
			imgui.separator()
			
			_, s2_node_input = imgui.input_text("Node ID (hex)", s2_node_input, 256)
			_, s2_dsk_input = imgui.input_text("DSK", s2_dsk_input, 256)
			
			imgui.text("")
			
			if imgui.button("Add DSK", width=150, height=40):
				if s2_node_input and s2_dsk_input:
					success = s2_manager.add_dsk(s2_node_input, s2_dsk_input)
					if success:
						cprint(f"[GUI] DSK added for node {s2_node_input}", Colors.OKGREEN, bold=True)
						s2_node_input = ""
						s2_dsk_input = ""
				else:
					cprint("[GUI] Please enter both Node ID and DSK", Colors.FAIL)
			
			imgui.same_line()
			if imgui.button("Clear", width=150, height=40):
				s2_node_input = ""
				s2_dsk_input = ""
			
			imgui.separator()
			
			imgui.text("Current DSKs:")
			imgui.begin_child("CurrentDSKs", width=0, height=100, border=True)
			if s2_manager.known_dsks:
				for node_id, dsk in s2_manager.known_dsks.items():
					imgui.text(f"Node {node_id}: {dsk.hex()}")
			else:
				imgui.text_colored("No DSKs configured yet", 0.7, 0.7, 0.7)
			imgui.end_child()
			
		imgui.end()

	imgui.render()

def impl_glfw_init(width, height, window_name):
	if not glfw.init():
		print("Could not initialize OpenGL context")
		sys.exit(1)

	glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
	glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
	glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
	glfw.window_hint(glfw.OPENGL_FORWARD_COMPAT, gl.GL_TRUE)

	window = glfw.create_window(width, height, window_name, None, None)
	glfw.make_context_current(window)

	if not window:
		glfw.terminate()
		print("Could not initialize Window")
		sys.exit(1)

	return window

def help_function():
	cprint("Z-Attack 1.0", Colors.HEADER, bold=True)
	print("-d [DEBUG]")
	print("-csv [CSV output]")
	print("-1 [Rfcat] [DEFAULT]")
	print("-2 [TI RF KIT]")
	print("-lcom COM1 [LISTENING PORT] [TI RF KIT]")
	print("-scom COM2 [SENDING PORT] [TI RF KIT]")
	cprint("Author: Advens", Colors.OKBLUE)
	cprint("Reloaded by: Penthertz", Colors.OKCYAN)
	cprint("Website: https://penthertz.com", Colors.OKGREEN)
	exit(0)

def license():
	cprint("Z-Attack Copyright (C) 2025 Advens", Colors.HEADER, bold=True)
	cprint("Reloaded by Penthertz - https://penthertz.com", Colors.OKCYAN, bold=True)
	print("")
	cprint("This program comes with ABSOLUTELY NO WARRANTY;", Colors.WARNING)
	cprint("This is free software, and you are welcome to redistribute it under certain conditions;", Colors.OKGREEN)

def main():
	global d, debug, fOutput, serialListen, deviceData, scom
	global logo_texture, logo_width, logo_height, window_impl, is_running
	
	# Register cleanup function
	atexit.register(cleanup)
	
	# Register signal handler for Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)
	
	fOutput = 1
	lcom = scom = ""
	deviceData = 1

	argc = len(sys.argv)
	for i in range(argc):
		s = sys.argv[i]
		if i < argc:
			if s in ("-d"):
				debug = 1
			if s in ("-csv"):
				fOutput = 1
			if s in ("-h"):
				help_function()
				exit(0)
			if s in ("-1"):
				deviceData = 1
			if s in ("-2"):
				deviceData = 2
			if s in ("-lcom"):
				lcom = sys.argv[i + 1]
			if s in ("-scom"):
				scom = sys.argv[i + 1]

	if deviceData == 2:
		if lcom and scom:
			try:
				serialListen = serial.Serial(port=lcom, baudrate=115000, bytesize=serial.EIGHTBITS,
											 parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=0)
			except:
				cprint(f"Error with {lcom}", Colors.FAIL, bold=True)
				exit(0)
		else:
			cprint("With -2 option, 'lcom' and 'scom' must be set", Colors.FAIL, bold=True)
			exit(0)
	else:
		try:
			d = RfCat(0, debug=False)
			d.setFreq(868399841)
			d.setMdmModulation(MOD_2FSK)
			d.setMdmSyncWord(0xaa0f)
			d.setMdmDeviatn(20629.883)
			d.setMdmChanSpc(199951.172)
			d.setMdmChanBW(101562.5)
			d.setMdmDRate(39970.4)
			d.makePktFLEN(48)
			d.setEnableMdmManchester(False)
			d.setMdmSyncMode(SYNCM_CARRIER_15_of_16)
		except Exception as e:
			cprint(f"Warning: Could not initialize RfCat device: {str(e)}", Colors.WARNING, bold=True)

	license()

	# Initialize ImGui and GLFW
	window = impl_glfw_init(1400, 800, "Z-Attack")
	imgui.create_context()
	window_impl = GlfwRenderer(window)

	# Load logo texture
	logo_texture, logo_width, logo_height = load_texture("images/zattack.png")

	# Main loop with proper exit handling
	try:
		while not glfw.window_should_close(window) and is_running:
			glfw.poll_events()
			window_impl.process_inputs()
			
			# Process Z-Wave packets with error handling
			try:
				listeningMode()
			except KeyboardInterrupt:
				raise
			except Exception as e:
				if debug:
					cprint(f"Error in listeningMode: {str(e)}", Colors.FAIL)
			
			# Render GUI
			render_gui()
			
			gl.glClearColor(0.1, 0.1, 0.1, 1)
			gl.glClear(gl.GL_COLOR_BUFFER_BIT)
			
			window_impl.render(imgui.get_draw_data())
			glfw.swap_buffers(window)
	
	except KeyboardInterrupt:
		cprint("\n[*] Keyboard interrupt detected", Colors.WARNING, bold=True)
	except Exception as e:
		cprint(f"\n[!] Unexpected error: {str(e)}", Colors.FAIL, bold=True)
	finally:
		cleanup()

if __name__ == "__main__":
	main()