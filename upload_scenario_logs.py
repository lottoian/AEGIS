import os
import gzip
import base64
import struct
import requests
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8080")
DEVICE_ID = os.getenv("DEVICE_ID", "240c894c126a902f")

# Define mock log lines grouped by correct LogType
logs_by_type = {
    "AntiForensicLog": (
        "2025-06-24 18:53:59 Anti-forensic event detected: android.intent.action.TIME_SET\n"
        "2025-06-24 18:53:59 SystemClockTime: Setting time of day to sec=1750758839221\n"
        "2025-06-24 18:53:59 Auto time setting enabled: false\n"
        "2025-06-24 18:54:41 Log Buffer Cleared Detected. (adb logcat -c)"
    ),
    "CallingLog": (
        "2025-06-24 18:54:05 Call Type: start an outgoing call Number: 01065749080 Start Time: 2025-06-24 18:54:05 End Time: N/A Duration: 0 seconds\n"
        "2025-06-24 18:54:17 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-06-24 18:54:05 End Time: 2025-06-24 18:54:17 Duration: 12 seconds\n"
        "2025-06-24 18:55:43 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n"
        "2025-06-24 18:55:49 Call Type: Refuse incoming calls or don't answer Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n"
        "2025-07-01 18:53:25 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n"
        "2025-07-01 18:53:26 Call Type: start an incoming call Number: 01065749080 Start Time: 2025-07-01 18:53:26 End Time: N/A Duration: 0 seconds\n"
        "2025-07-01 18:53:32 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-07-01 18:53:26 End Time: 2025-07-01 18:53:32 Duration: 6 seconds"
    ),
    "MessageLog": (
        "2025-06-24 18:55:37 SMS Sent from: 01065749080 Message: Who are you?\n"
        "2025-07-01 18:53:41 SMS Received from: 01065749080 Message: Malicious Message"
    ),
    "BluetoothLog": (
        "2025-06-24 18:56:18 Bluetooth connected to: AirPods [60:93:16:44:B7:46]\n"
        "2025-06-24 18:56:21 A2DP streaming stopped on device: AirPods\n"
        "2025-06-24 18:57:05 A2DP streaming started on device: AirPods\n"
        "2025-06-24 18:57:16 A2DP streaming stopped on device: AirPods"
    ),
    "FileLog": (
        "2025-06-24 18:56:56 File Opened (file_opened): /storage/emulated/0/Music/Samsung/Over_the_Horizon.mp3\n"
        "2025-07-01 18:53:05 File Created: /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:11 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:11 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:13 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:17 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:17 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:17 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:17 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:47 File Opened (file_opened): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Closed without Writing (closed_without_writing): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Revised (written_to): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Closed after Writing (closed_after_write): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Accessed (read_from): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 MediaStore changed: content://media/external/images/media/1000000159File Name (DISPLAY_NAME): Screenshot_20240529_194105_Samsung Cloud.jpgRelative Path: DCIM/Screenshots/Modifed After Date: 2027-05-30 04:41:00\n"
        "2025-07-01 18:53:47 File change detected: Name: Screenshot_20240529_194105_Samsung Cloud.jpg, Path: DCIM/Screenshots/\n"
        "2025-07-01 18:53:47 File Metadata Changed (metadata_changed): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Accessed (read_from): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg"
    ),
    "AppExecutionLog": (
        "2025-06-24 18:53:59 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:54:00 Background App: com.android.settings\n"
        "2025-06-24 18:54:00 Foreground App: com.sec.android.app.launcher\n"
        "2025-06-24 18:54:02 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-06-24 18:54:02 Background App: com.sec.android.app.launcher\n"
        "2025-06-24 18:54:02 Foreground App: com.samsung.android.dialer\n"
        "2025-06-24 18:54:03 Text: 010-6574-9080 Class Name: android.view.ViewGroup Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:54:05 Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:54:05 Background App: com.samsung.android.dialer\n"
        "2025-06-24 18:54:05 Foreground App: com.skt.prod.dialer\n"
        "2025-06-24 18:54:14 Background App: com.skt.prod.dialer\n"
        "2025-06-24 18:54:14 Foreground App: com.android.systemui\n"
        "2025-06-24 18:54:22 Background App: com.android.systemui\n"
        "2025-06-24 18:54:22 Foreground App: com.samsung.android.dialer\n"
        "2025-06-24 18:55:26 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:55:26 Background App: com.samsung.android.dialer\n"
        "2025-06-24 18:55:26 Foreground App: com.sec.android.app.launcher\n"
        "2025-06-24 18:55:27 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-06-24 18:55:27 Background App: com.sec.android.app.launcher\n"
        "2025-06-24 18:55:27 Foreground App: com.samsung.android.messaging\n"
        "2025-06-24 18:55:28 Text: Class Name: android.widget.EditText Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:55:28 Background App: com.samsung.android.messaging\n"
        "2025-06-24 18:55:28 Foreground App: com.samsung.android.honeyboard\n"
        "2025-06-24 18:55:32 Background App: com.samsung.android.honeyboard\n"
        "2025-06-24 18:55:32 Foreground App: com.samsung.android.messaging\n"
        "2025-06-24 18:55:35 Text: Text message Class Name: android.widget.EditText Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:55:44 Background App: com.samsung.android.messaging\n"
        "2025-06-24 18:55:44 Foreground App: com.skt.prod.dialer\n"
        "2025-06-24 18:55:49 Text: Swipe right to answer and left to reject. Content Description: Swipe right to answer and left to reject. Class Name: android.view.View Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:55:49 Background App: com.skt.prod.dialer\n"
        "2025-06-24 18:55:49 Foreground App: com.samsung.android.messaging\n"
        "2025-06-24 18:56:12 Background App: com.samsung.android.messaging\n"
        "2025-06-24 18:56:12 Foreground App: com.android.systemui\n"
        "2025-06-24 18:56:16 Text: WanYI Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:56:23 Text: Done Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:56:24 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:56:24 Background App: com.android.systemui\n"
        "2025-06-24 18:56:24 Foreground App: com.sec.android.app.launcher\n"
        "2025-06-24 18:56:56 Text: ... Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-06-24 18:56:56 Background App: com.sec.android.app.launcher\n"
        "2025-06-24 18:56:56 Foreground App: com.iloen.melon\n"
        "2025-06-24 18:57:33 Background App: com.iloen.melon\n"
        "2025-06-24 18:57:33 Foreground App: com.android.systemui\n"
        "2025-06-24 18:57:34 Text: Tap again to restart your phone Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-06-24 18:57:39 Text: Restart, Content Description: Restart, Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:57:40 Background App: com.android.systemui\n"
        "2025-06-24 18:57:40 Foreground App: android\n"
        "2025-07-01 18:52:55 Foreground App: com.android.settings\n"
        "2025-07-01 18:52:56 Text: Back Content Description: Back Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:52:56 Background App: com.android.settings\n"
        "2025-07-01 18:52:56 Foreground App: com.example.logcat\n"
        "2025-07-01 18:52:57 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:52:57 Background App: com.example.logcat\n"
        "2025-07-01 18:52:57 Foreground App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:08 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-07-01 18:53:08 Background App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:08 Foreground App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:09 Text: Attacker File.txt, Jul 1 6:53 PM, 32 B Content Description: Attacker File.txt, Jul 1 6:53 PM, 32 B Class Name: android.widget.Image Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:10 Background App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:10 Foreground App: android\n"
        "2025-07-01 18:53:10 Text: Just once Content Description: Use selected app just once Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:11 Background App: android\n"
        "2025-07-01 18:53:11 Foreground App: com.folderv.file\n"
        "2025-07-01 18:53:12 Text: Hello I am a Android Attacker!!! Class Name: android.view.View Clickable: false, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:13 Background App: com.folderv.file\n"
        "2025-07-01 18:53:13 Foreground App: com.samsung.android.honeyboard\n"
        "2025-07-01 18:53:16 Text: Back Content Description: Back Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:17 Background App: com.samsung.android.honeyboard\n"
        "2025-07-01 18:53:17 Foreground App: com.folderv.file\n"
        "2025-07-01 18:53:18 Background App: com.folderv.file\n"
        "2025-07-01 18:53:18 Foreground App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:25 Background App: com.folderv.file\n"
        "2025-07-01 18:53:25 Foreground App: com.skt.prod.dialer\n"
        "2025-07-01 18:53:26 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-07-01 18:53:29 Background App: com.skt.prod.dialer\n"
        "2025-07-01 18:53:29 Foreground App: com.android.systemui\n"
        "2025-07-01 18:53:37 Background App: com.android.systemui\n"
        "2025-07-01 18:53:37 Foreground App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:41 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:41 Background App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:41 Foreground App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:42 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-07-01 18:53:42 Background App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:42 Foreground App: com.sec.android.gallery3d\n"
        "2025-07-01 18:53:44 Text: Edit Content Description: Edit Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:45 Text: Saturday, May 30, 20264:41AM Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:46 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-07-01 18:53:47 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-07-01 18:53:48 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:48 Background App: com.sec.android.gallery3d\n"
        "2025-07-01 18:53:48 Foreground App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:56 Text: Set date Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:56 Background App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:56 Foreground App: com.android.settings\n"
        "2025-07-01 18:53:57 Text: Previous month Content Description: Previous month Class Name: android.widget.ImageButton Clickable: true, Enabled: true, Focusable: true"
    )
}

print("=== AEGIS Scenario Logs Uploader ===")

# 1. Fetch Server Ephemeral Public Key
try:
    print(f"[*] Fetching server X25519 public key from {SERVER_URL}/logs/serverkey...")
    response = requests.get(f"{SERVER_URL}/logs/serverkey", verify=False, timeout=5)
    if response.status_code == 200:
        server_pub_b64 = response.text.strip()
        server_pub_bytes = base64.b64decode(server_pub_b64)
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        server_public_key = load_der_public_key(server_pub_bytes)
        print("[+] Successfully fetched server X25519 public key!")
    else:
        raise Exception(f"Failed to fetch key. Status code: {response.status_code}")
except Exception as e:
    print(f"[!] Server connection failed ({e}). Exiting...")
    exit(1)

# Generate Client Ephemeral KeyPair (X25519)
client_private_key = x25519.X25519PrivateKey.generate()
client_public_key = client_private_key.public_key()
ephemeral_pub_bytes = client_public_key.public_bytes(
    encoding=Encoding.Raw,
    format=PublicFormat.Raw
)

# Key Agreement
shared_secret = client_private_key.exchange(server_public_key)

# HKDF Key Derivation (AES-256 Key)
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'\x00' * 32,
    info=b''
)
session_key = hkdf.derive(shared_secret)
print("[+] Derived Session Key via ECDH + HKDF!")

# Generate Signing Key Pair
signing_private_key = ec.generate_private_key(ec.SECP256R1())

# Loop through each log type and upload
for log_type, log_content in logs_by_type.items():
    print(f"\n[*] Processing log type: {log_type}...")
    
    # GZIP Compress
    compressed_data = gzip.compress(log_content.encode('utf-8'))
    
    # AES-256-GCM Encrypt
    iv = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(iv, compressed_data, DEVICE_ID.encode('utf-8'))
    
    # ECDSA Sign
    signature_data = ephemeral_pub_bytes + iv + DEVICE_ID.encode('utf-8') + ciphertext
    signature = signing_private_key.sign(
        signature_data,
        ec.ECDSA(hashes.SHA256())
    )
    
    # Build Binary Payload Packet
    payload = struct.pack(">I", len(ephemeral_pub_bytes)) + ephemeral_pub_bytes
    payload += iv
    payload += struct.pack(">I", len(signature)) + signature
    payload += ciphertext
    
    # Calculate Chain Hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(log_content.encode('utf-8'))
    chain_hash = digest.finalize().hex()
    
    # HTTP Upload to Spring Boot
    files = {
        'logFile': (f"{DEVICE_ID}_{log_type}.txt", payload, 'application/octet-stream'),
        'hashFile': (f"{DEVICE_ID}_{log_type}_hash.txt", chain_hash.encode('utf-8'), 'text/plain')
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/logs/upload", files=files, timeout=10)
        print(f"[{log_type} Status Code]: {response.status_code}")
        print(f"[{log_type} Server Response]: {response.text.strip()}")
    except Exception as e:
        print(f"[!] Upload failed for {log_type}: {e}")

print("\n=================================================")
