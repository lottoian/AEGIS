package com.example.forensic;

import com.example.forensic.Service.CryptoService;
import com.example.forensic.Service.HashService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.example.forensic.Service.LogService;
import com.example.forensic.Repository.LogRepository;
import java.time.LocalDateTime;
import org.springframework.mock.web.MockMultipartFile;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SecuritySystemTests {

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private HashService hashService;

    @Autowired
    private LogService logService;

    @Autowired
    private LogRepository logRepository;

    @Test
    void testReportGenerationHashMatch() throws Exception {
        logRepository.deleteAll();

        String deviceId = "test_device_hash_match";
        String logType = "SecurityTamperLog";
        String decryptedLogContent = 
            "2026-06-06 14:10:00 Frida instrumentation tool detected in memory.\n" +
            "2026-06-06 14:10:01 Terminating execution due to security policy violations.";

        String expectedHash = hashService.calculateMessageHash(decryptedLogContent);

        MockMultipartFile hashFile = new MockMultipartFile(
                "hashFile",
                "hash.txt",
                "text/plain",
                expectedHash.getBytes(StandardCharsets.UTF_8)
        );

        String appendResult = logService.appendDecryptedLog(deviceId, logType, decryptedLogContent, hashFile);
        assertEquals("SUCCESS", appendResult);

        LocalDateTime start = LocalDateTime.of(2026, 6, 6, 0, 0, 0);
        LocalDateTime end = LocalDateTime.of(2026, 6, 6, 23, 59, 59);
        String reportPath = logService.analyzeLog(deviceId, start, end);

        java.nio.file.Path logFilePath = java.nio.file.Paths.get("/app/reports", "logs_" + expectedHash + ".txt");
        assertTrue(java.nio.file.Files.exists(logFilePath));

        String calculatedFileHash = hashService.calculateFileHash(logFilePath);
        assertEquals(expectedHash, calculatedFileHash);
    }

    @Test
    void testAEGISReportScenario() throws Exception {
        logRepository.deleteAll();

        String deviceId = "240c894c126a902f";
        String logType = "SecurityTamperLog";
        
        String decryptedLogContent = 
            "2025-06-24 18:53:59 Anti-forensic event detected: android.intent.action.TIME_SET\n" +
            "2025-06-24 18:53:59 SystemClockTime: Setting time of day to sec=1750758839221\n" +
            "2025-06-24 18:53:59 Auto time setting enabled: false\n" +
            "2025-06-24 18:54:41 Log Buffer Cleared Detected. (adb logcat -c)\n" +
            "2025-06-24 18:54:05 Call Type: start an outgoing call Number: 01065749080 Start Time: 2025-06-24 18:54:05 End Time: N/A Duration: 0 seconds\n" +
            "2025-06-24 18:54:17 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-06-24 18:54:05 End Time: 2025-06-24 18:54:17 Duration: 12 seconds\n" +
            "2025-06-24 18:55:43 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
            "2025-06-24 18:55:49 Call Type: Refuse incoming calls or don't answer Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
            "2025-07-01 18:53:25 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
            "2025-07-01 18:53:26 Call Type: start an incoming call Number: 01065749080 Start Time: 2025-07-01 18:53:26 End Time: N/A Duration: 0 seconds\n" +
            "2025-07-01 18:53:32 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-07-01 18:53:26 End Time: 2025-07-01 18:53:32 Duration: 6 seconds\n" +
            "2025-06-24 18:55:37 SMS Sent from: 01065749080 Message: Who are you?\n" +
            "2025-07-01 18:53:41 SMS Received from: 01065749080 Message: Malicious Message\n" +
            "2025-06-24 18:56:18 Bluetooth connected to: AirPods [60:93:16:44:B7:46]\n" +
            "2025-06-24 18:56:21 A2DP streaming stopped on device: AirPods\n" +
            "2025-06-24 18:57:05 A2DP streaming started on device: AirPods\n" +
            "2025-06-24 18:57:16 A2DP streaming stopped on device: AirPods\n" +
            "2025-06-24 18:56:56 File Opened (file_opened): /storage/emulated/0/Music/Samsung/Over_the_Horizon.mp3\n" +
            "2025-07-01 18:53:05 File Created: /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:05 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:05 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:05 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:05 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:11 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:11 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:13 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:17 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:17 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:17 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:17 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:47 File Opened (file_opened): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-07-01 18:53:47 File Closed without Writing (closed_without_writing): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-07-01 18:53:47 File Revised (written_to): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-07-01 18:53:47 File Closed after Writing (closed_after_write): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-07-01 18:53:47 File Accessed (read_from): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-07-01 18:53:47 MediaStore changed: content://media/external/images/media/1000000159File Name (DISPLAY_NAME): Screenshot_20240529_194105_Samsung Cloud.jpgRelative Path: DCIM/Screenshots/Modifed After Date: 2027-05-30 04:41:00\n" +
            "2025-07-01 18:53:47 File change detected: Name: Screenshot_20240529_194105_Samsung Cloud.jpg, Path: DCIM/Screenshots/\n" +
            "2025-07-01 18:53:47 File Metadata Changed (metadata_changed): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-07-01 18:53:47 File Accessed (read_from): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-06-24 18:53:59 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:54:00 Background App: com.android.settings\n" +
            "2025-06-24 18:54:00 Foreground App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:54:02 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-06-24 18:54:02 Background App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:54:02 Foreground App: com.samsung.android.dialer\n" +
            "2025-06-24 18:54:03 Text: 010-6574-9080 Class Name: android.view.ViewGroup Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:54:05 Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:54:05 Background App: com.samsung.android.dialer\n" +
            "2025-06-24 18:54:05 Foreground App: com.skt.prod.dialer\n" +
            "2025-06-24 18:54:14 Background App: com.skt.prod.dialer\n" +
            "2025-06-24 18:54:14 Foreground App: com.android.systemui\n" +
            "2025-06-24 18:54:22 Background App: com.android.systemui\n" +
            "2025-06-24 18:54:22 Foreground App: com.samsung.android.dialer\n" +
            "2025-06-24 18:55:26 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:55:26 Background App: com.samsung.android.dialer\n" +
            "2025-06-24 18:55:26 Foreground App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:55:27 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-06-24 18:55:27 Background App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:55:27 Foreground App: com.samsung.android.messaging\n" +
            "2025-06-24 18:55:28 Text: Class Name: android.widget.EditText Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:55:28 Background App: com.samsung.android.messaging\n" +
            "2025-06-24 18:55:28 Foreground App: com.samsung.android.honeyboard\n" +
            "2025-06-24 18:55:32 Background App: com.samsung.android.honeyboard\n" +
            "2025-06-24 18:55:32 Foreground App: com.samsung.android.messaging\n" +
            "2025-06-24 18:55:35 Text: Text message Class Name: android.widget.EditText Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:55:44 Background App: com.samsung.android.messaging\n" +
            "2025-06-24 18:55:44 Foreground App: com.skt.prod.dialer\n" +
            "2025-06-24 18:55:49 Text: Swipe right to answer and left to reject. Content Description: Swipe right to answer and left to reject. Class Name: android.view.View Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:55:49 Background App: com.skt.prod.dialer\n" +
            "2025-06-24 18:55:49 Foreground App: com.samsung.android.messaging\n" +
            "2025-06-24 18:56:12 Background App: com.samsung.android.messaging\n" +
            "2025-06-24 18:56:12 Foreground App: com.android.systemui\n" +
            "2025-06-24 18:56:16 Text: WanYI Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:56:23 Text: Done Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:56:24 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:56:24 Background App: com.android.systemui\n" +
            "2025-06-24 18:56:24 Foreground App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:56:56 Text: ... Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-06-24 18:56:56 Background App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:56:56 Foreground App: com.iloen.melon\n" +
            "2025-06-24 18:57:33 Background App: com.iloen.melon\n" +
            "2025-06-24 18:57:33 Foreground App: com.android.systemui\n" +
            "2025-06-24 18:57:34 Text: Tap again to restart your phone Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-06-24 18:57:39 Text: Restart, Content Description: Restart, Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-06-24 18:57:40 Background App: com.android.systemui\n" +
            "2025-06-24 18:57:40 Foreground App: android\n" +
            "2025-07-01 18:52:55 Foreground App: com.android.settings\n" +
            "2025-07-01 18:52:56 Text: Back Content Description: Back Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:52:56 Background App: com.android.settings\n" +
            "2025-07-01 18:52:56 Foreground App: com.example.logcat\n" +
            "2025-07-01 18:52:57 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:52:57 Background App: com.example.logcat\n" +
            "2025-07-01 18:52:57 Foreground App: com.sec.android.app.launcher\n" +
            "2025-07-01 18:53:08 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-07-01 18:53:08 Background App: com.sec.android.app.launcher\n" +
            "2025-07-01 18:53:08 Foreground App: com.sec.android.app.myfiles\n" +
            "2025-07-01 18:53:09 Text: Attacker File.txt, Jul 1 6:53 PM, 32 B Content Description: Attacker File.txt, Jul 1 6:53 PM, 32 B Class Name: android.widget.Image Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:10 Background App: com.sec.android.app.myfiles\n" +
            "2025-07-01 18:53:10 Foreground App: android\n" +
            "2025-07-01 18:53:10 Text: Just once Content Description: Use selected app just once Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:11 Background App: android\n" +
            "2025-07-01 18:53:11 Foreground App: com.folderv.file\n" +
            "2025-07-01 18:53:12 Text: Hello I am a Android Attacker!!! Class Name: android.view.View Clickable: false, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:13 Background App: com.folderv.file\n" +
            "2025-07-01 18:53:13 Foreground App: com.samsung.android.honeyboard\n" +
            "2025-07-01 18:53:16 Text: Back Content Description: Back Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:17 Background App: com.samsung.android.honeyboard\n" +
            "2025-07-01 18:53:17 Foreground App: com.folderv.file\n" +
            "2025-07-01 18:53:18 Background App: com.folderv.file\n" +
            "2025-07-01 18:53:18 Foreground App: com.sec.android.app.myfiles\n" +
            "2025-07-01 18:53:25 Background App: com.folderv.file\n" +
            "2025-07-01 18:53:25 Foreground App: com.skt.prod.dialer\n" +
            "2025-07-01 18:53:26 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-07-01 18:53:29 Background App: com.skt.prod.dialer\n" +
            "2025-07-01 18:53:29 Foreground App: com.android.systemui\n" +
            "2025-07-01 18:53:37 Background App: com.android.systemui\n" +
            "2025-07-01 18:53:37 Foreground App: com.sec.android.app.myfiles\n" +
            "2025-07-01 18:53:41 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:41 Background App: com.sec.android.app.myfiles\n" +
            "2025-07-01 18:53:41 Foreground App: com.sec.android.app.launcher\n" +
            "2025-07-01 18:53:42 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-07-01 18:53:42 Background App: com.sec.android.app.launcher\n" +
            "2025-07-01 18:53:42 Foreground App: com.sec.android.gallery3d\n" +
            "2025-07-01 18:53:44 Text: Edit Content Description: Edit Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:45 Text: Saturday, May 30, 20264:41AM Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:46 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-07-01 18:53:47 Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n" +
            "2025-07-01 18:53:48 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:48 Background App: com.sec.android.gallery3d\n" +
            "2025-07-01 18:53:48 Foreground App: com.sec.android.app.launcher\n" +
            "2025-07-01 18:53:56 Text: Set date Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n" +
            "2025-07-01 18:53:56 Background App: com.sec.android.app.launcher\n" +
            "2025-07-01 18:53:56 Foreground App: com.android.settings\n" +
            "2025-07-01 18:53:57 Text: Previous month Content Description: Previous month Class Name: android.widget.ImageButton Clickable: true, Enabled: true, Focusable: true";

        String expectedHash = hashService.calculateMessageHash(decryptedLogContent);

        MockMultipartFile hashFile = new MockMultipartFile(
                "hashFile",
                "hash.txt",
                "text/plain",
                expectedHash.getBytes(StandardCharsets.UTF_8)
        );

        String appendResult = logService.appendDecryptedLog(deviceId, logType, decryptedLogContent, hashFile);
        assertEquals("SUCCESS", appendResult);

        LocalDateTime start = LocalDateTime.of(2025, 2, 1, 14, 0, 0);
        LocalDateTime end = LocalDateTime.of(2026, 12, 31, 23, 59, 59);
        String reportPath = logService.analyzeLog(deviceId, start, end);

        java.nio.file.Path logFilePath = java.nio.file.Paths.get("/app/reports", "logs_" + expectedHash + ".txt");
        assertTrue(java.nio.file.Files.exists(logFilePath));

        String calculatedFileHash = hashService.calculateFileHash(logFilePath);
        assertEquals(expectedHash, calculatedFileHash);
    }

    @Test
    void testE2EDecryptionAndVerification() throws Exception {
        String originalLog = "2026-06-06 14:00:00 [INFO] Test Log Content\n2026-06-06 14:01:00 [WARN] Memory Alert";
        String deviceId = "test_device_01";

        // 1. Get server public key
        byte[] serverPublicKeyBytes = cryptoService.getServerPublicKeyBytes();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

        // 2. Generate client Ephemeral KeyPair (X25519)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair clientEphemeralKeyPair = kpg.generateKeyPair();
        byte[] ephemeralPublicKeyBytes = clientEphemeralKeyPair.getPublic().getEncoded();

        // 3. Client ECDH Key Agreement
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(clientEphemeralKeyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // 4. Derive session key using HKDF-SHA256
        byte[] sessionKeyBytes = deriveHKDFKey(sharedSecret);
        SecretKeySpec sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        // 5. GZIP compress original log
        byte[] compressedPlaintext = compressGZIP(originalLog);

        // 6. AES-256-GCM Encrypt
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
        cipher.updateAAD(deviceId.getBytes());
        byte[] ciphertext = cipher.doFinal(compressedPlaintext);

        // 7. Client signing key pair (ECDSA Secp256r1)
        KeyPairGenerator ecdsaKpg = KeyPairGenerator.getInstance("EC");
        ecdsaKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair clientSigningKeyPair = ecdsaKpg.generateKeyPair();
        PublicKey clientSigningPublicKey = clientSigningKeyPair.getPublic();

        // Sign over: EphemeralKeyBytes + IV + DeviceId + Ciphertext
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(clientSigningKeyPair.getPrivate());
        sig.update(ephemeralPublicKeyBytes);
        sig.update(iv);
        sig.update(deviceId.getBytes());
        sig.update(ciphertext);
        byte[] signatureBytes = sig.sign();

        // 8. Build complete payload package
        ByteBuffer buffer = ByteBuffer.allocate(
                4 + ephemeralPublicKeyBytes.length + 12 + 4 + signatureBytes.length + ciphertext.length
        );
        buffer.putInt(ephemeralPublicKeyBytes.length);
        buffer.put(ephemeralPublicKeyBytes);
        buffer.put(iv);
        buffer.putInt(signatureBytes.length);
        buffer.put(signatureBytes);
        buffer.put(ciphertext);

        byte[] finalPacket = buffer.array();

        // 9. Server decrypts and verifies
        String decryptedContent = cryptoService.decryptAndVerify(finalPacket, clientSigningPublicKey, deviceId);

        assertEquals(originalLog, decryptedContent);
    }

    @Test
    void testInvalidSignatureThrowsSecurityException() throws Exception {
        String originalLog = "2026-06-06 14:00:00 [INFO] Corrupted Signature Test";
        String deviceId = "test_device_02";

        byte[] serverPublicKeyBytes = cryptoService.getServerPublicKeyBytes();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair clientEphemeralKeyPair = kpg.generateKeyPair();
        byte[] ephemeralPublicKeyBytes = clientEphemeralKeyPair.getPublic().getEncoded();

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(clientEphemeralKeyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        byte[] sessionKeyBytes = deriveHKDFKey(sharedSecret);
        SecretKeySpec sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
        byte[] compressedPlaintext = compressGZIP(originalLog);

        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
        cipher.updateAAD(deviceId.getBytes());
        byte[] ciphertext = cipher.doFinal(compressedPlaintext);

        KeyPairGenerator ecdsaKpg = KeyPairGenerator.getInstance("EC");
        ecdsaKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair clientSigningKeyPair = ecdsaKpg.generateKeyPair();
        PublicKey clientSigningPublicKey = clientSigningKeyPair.getPublic();

        // Let's sign a different dataset or corrupt signature
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(clientSigningKeyPair.getPrivate());
        sig.update(new byte[5]); // Corrupted data
        byte[] signatureBytes = sig.sign();

        ByteBuffer buffer = ByteBuffer.allocate(
                4 + ephemeralPublicKeyBytes.length + 12 + 4 + signatureBytes.length + ciphertext.length
        );
        buffer.putInt(ephemeralPublicKeyBytes.length);
        buffer.put(ephemeralPublicKeyBytes);
        buffer.put(iv);
        buffer.putInt(signatureBytes.length);
        buffer.put(signatureBytes);
        buffer.put(ciphertext);

        byte[] finalPacket = buffer.array();

        assertThrows(SecurityException.class, () -> {
            cryptoService.decryptAndVerify(finalPacket, clientSigningPublicKey, deviceId);
        });
    }

    private byte[] deriveHKDFKey(byte[] sharedSecret) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        SecretKeySpec salt = new SecretKeySpec(new byte[32], "HmacSHA256");
        mac.init(salt);
        byte[] prk = mac.doFinal(sharedSecret);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 1);
        return mac.doFinal();
    }

    private byte[] compressGZIP(String data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(data.getBytes(StandardCharsets.UTF_8));
        }
        return baos.toByteArray();
    }
}
