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
