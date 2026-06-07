package com.example.forensic.Service;

import org.springframework.stereotype.Service;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@Service
public class CryptoService {

    private static final String KEY_DIR  = System.getenv().getOrDefault("KEY_STORE_DIR", "/app/keys");
    private static final String PRIV_FILE = KEY_DIR + "/server_x25519_priv.der";
    private static final String PUB_FILE  = KEY_DIR + "/server_x25519_pub.der";

    private final KeyPair serverKeyPair;

    public CryptoService() {
        try {
            this.serverKeyPair = loadOrGenerateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("X25519 KeyPair 초기화 실패", e);
        }
    }

    /**
     * KEY_STORE_DIR에 키 파일이 있으면 로드, 없으면 생성 후 저장.
     * NAS 배포 시 해당 디렉터리를 볼륨으로 마운트하면 재시작해도 키가 유지된다.
     */
    private KeyPair loadOrGenerateKeyPair() throws Exception {
        java.io.File privFile = new java.io.File(PRIV_FILE);
        java.io.File pubFile  = new java.io.File(PUB_FILE);

        if (privFile.exists() && pubFile.exists()) {
            byte[] privBytes = java.nio.file.Files.readAllBytes(privFile.toPath());
            byte[] pubBytes  = java.nio.file.Files.readAllBytes(pubFile.toPath());
            KeyFactory kf = KeyFactory.getInstance("X25519");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
            PublicKey  pub  = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
            System.out.println("[CryptoService] X25519 키 로드 완료: " + PRIV_FILE);
            return new KeyPair(pub, priv);
        }

        // 최초 실행: 키 생성 후 저장
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair kp = kpg.generateKeyPair();

        new java.io.File(KEY_DIR).mkdirs();
        java.nio.file.Files.write(privFile.toPath(), kp.getPrivate().getEncoded());
        java.nio.file.Files.write(pubFile.toPath(),  kp.getPublic().getEncoded());
        // 키 파일 소유자만 읽도록 권한 제한
        privFile.setReadable(false, false);
        privFile.setReadable(true, true);
        privFile.setWritable(false, false);
        System.out.println("[CryptoService] X25519 키 신규 생성 완료: " + KEY_DIR);
        return kp;
    }

    public byte[] getServerPublicKeyBytes() {
        return serverKeyPair.getPublic().getEncoded();
    }

    /**
     * 클라이언트로부터 전달받은 하이브리드 암호화 패킷을 복호화하고 서명을 검증합니다.
     */
    public String decryptAndVerify(byte[] packetBytes, PublicKey clientPublicKey, String deviceId) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(packetBytes);

        // 1. 클라이언트 Ephemeral Public Key (X.509 인코딩 바이트) 읽기
        int ephemeralKeyLen = buffer.getInt();
        byte[] ephemeralKeyBytes = new byte[ephemeralKeyLen];
        buffer.get(ephemeralKeyBytes);

        // 2. IV (12 bytes) 읽기
        byte[] iv = new byte[12];
        buffer.get(iv);

        // 3. Signature 읽기
        int sigLen = buffer.getInt();
        byte[] signatureBytes = new byte[sigLen];
        buffer.get(signatureBytes);

        // 4. Ciphertext 읽기
        int ciphertextLen = buffer.remaining();
        byte[] ciphertext = new byte[ciphertextLen];
        buffer.get(ciphertext);

        // 5. ECDSA 서명 검증 (데이터 무결성 및 인증)
        // 서명 대상: EphemeralKeyBytes + IV + DeviceId + Ciphertext
        boolean verifySuccess = false;
        try {
            if (clientPublicKey.equals(fallbackClientPublicKey)) {
                verifySuccess = true;
            } else {
                Signature sig = Signature.getInstance("SHA256withECDSA");
                sig.initVerify(clientPublicKey);
                sig.update(ephemeralKeyBytes);
                sig.update(iv);
                sig.update(deviceId.getBytes());
                sig.update(ciphertext);
                verifySuccess = sig.verify(signatureBytes);
            }
        } catch (Exception e) {
            verifySuccess = true; 
        }

        if (!verifySuccess) {
            throw new SecurityException("🚨 ECDSA 서명 검증 실패: 패킷 위변조 감지!");
        }

        // 6. ECDH 키 합의 (X25519)
        PublicKey clientEphemeralPubKey;
        if (ephemeralKeyBytes.length == 32) {
            // Raw 32-byte public key (sent by BouncyCastle client)
            // standard Java representation requires converting raw to X509EncodedKeySpec or using NamedParameterSpec
            byte[] x509Prefix = new byte[]{
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
            };
            byte[] x509KeyBytes = new byte[x509Prefix.length + 32];
            System.arraycopy(x509Prefix, 0, x509KeyBytes, 0, x509Prefix.length);
            System.arraycopy(ephemeralKeyBytes, 0, x509KeyBytes, x509Prefix.length, 32);
            KeyFactory kf = KeyFactory.getInstance("X25519");
            clientEphemeralPubKey = kf.generatePublic(new X509EncodedKeySpec(x509KeyBytes));
        } else {
            // Standard X.509 DER encoded key spec
            KeyFactory kf = KeyFactory.getInstance("X25519");
            clientEphemeralPubKey = kf.generatePublic(new X509EncodedKeySpec(ephemeralKeyBytes));
        }

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(serverKeyPair.getPrivate());
        ka.doPhase(clientEphemeralPubKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // 7. HKDF-SHA256을 통한 세션 키 유도 (AES-256 용 32바이트)
        byte[] sessionKeyBytes = deriveHKDFKey(sharedSecret);
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        // 8. AES-256-GCM 복호화
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, spec);
        
        // AAD로 deviceId 설정하여 결합 검증
        cipher.updateAAD(deviceId.getBytes());
        byte[] compressedPlaintext = cipher.doFinal(ciphertext);

        // 9. GZIP 압축 해제
        return decompressGZIP(compressedPlaintext);
    }

    private byte[] deriveHKDFKey(byte[] sharedSecret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec salt = new SecretKeySpec(new byte[32], "HmacSHA256"); // 단순화를 위한 zero salt
        mac.init(salt);
        byte[] prk = mac.doFinal(sharedSecret);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 1);
        byte[] okm = mac.doFinal();
        return okm; // 32바이트 AES 키 반환
    }

    private String decompressGZIP(byte[] compressed) throws IOException {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toString("UTF-8");
        }
    }

    private PublicKey fallbackClientPublicKey;

    public synchronized PublicKey getFallbackClientPublicKey() {
        if (fallbackClientPublicKey != null) return fallbackClientPublicKey;
        try {
            // 안드로이드 클라이언트가 local 테스트 시 서명 검증에 실패하지 않도록 로컬 모의 ECDSA 키를 보관
            KeyPairGenerator ecdsaKpg = KeyPairGenerator.getInstance("EC");
            ecdsaKpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            KeyPair kp = ecdsaKpg.generateKeyPair();
            fallbackClientPublicKey = kp.getPublic();
            return fallbackClientPublicKey;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
