package com.example.logcat.manager;

import com.example.logcat.BuildConfig;
import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import com.example.logcat.queue.OfflineLogDatabase;
import com.example.logcat.queue.OfflineLogEntity;
import com.example.logcat.queue.UploadQueueWorker;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * 서버 전송 관리자.
 * - OkHttp + mTLS (클라이언트 인증서)
 * - SPKI 핀닝 (SHA256 핀)
 * - ClientCryptoPipeline으로 E2E 암호화 후 전송
 * - 네트워크 실패 시 SQLCipher 오프라인 큐에 저장 → WorkManager 재시도
 */
public class ServerTransmitter {

    private static final String TAG = "ServerTransmitter";
    private static final String BASE_URL = BuildConfig.BASE_URL;
    private static final String UPLOAD_PATH = "/logs/upload";
    private static final String TIMESTAMP_PATH = "/logs/timestamp";
    private static final String SERVERKEY_PATH = "/logs/serverkey";

    /**
     * 서버 인증서 SPKI SHA-256 핀 (실제 배포 시 certutil / openssl로 추출한 값 사용).
     * 형식: "sha256/Base64EncodedSPKIHash=="
     * 백업 핀 1개 필수 (인증서 갱신 대비).
     */
    private static final String SPKI_PIN_PRIMARY = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String SPKI_PIN_BACKUP  = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    private final Context context;
    private volatile OkHttpClient httpClient;
    private volatile ClientCryptoPipeline cryptoPipeline;
    private volatile byte[] cachedServerPublicKey;

    public ServerTransmitter(Context context) {
        this.context = context;
    }

    // ──────────────────────────────────────────────
    // OkHttp 클라이언트 초기화 (mTLS + SPKI 핀닝)
    // ──────────────────────────────────────────────

    private synchronized OkHttpClient getHttpClient() {
        if (httpClient != null) return httpClient;
        try {
            if (!BuildConfig.USE_MTLS) {
                httpClient = new OkHttpClient.Builder()
                        .connectTimeout(15, TimeUnit.SECONDS)
                        .readTimeout(30, TimeUnit.SECONDS)
                        .writeTimeout(30, TimeUnit.SECONDS)
                        .build();
                return httpClient;
            }
            // 클라이언트 인증서 키스토어 로드 (Android Keystore)
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, null);

            // 시스템 신뢰 저장소
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);

            SSLContext sslCtx = SSLContext.getInstance("TLSv1.3");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            sslCtx.init(kmf.getKeyManagers(), trustManagers, new SecureRandom());

            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

            String host = "";
            try {
                host = new java.net.URI(BASE_URL).getHost();
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse host from BASE_URL", e);
            }
            if (host == null || host.isEmpty()) {
                host = "220.149.236.152"; // fallback
            }

            // SPKI 핀닝 (주 핀 + 백업 핀)
            CertificatePinner pinner = new CertificatePinner.Builder()
                    .add(host, SPKI_PIN_PRIMARY)
                    .add(host, SPKI_PIN_BACKUP)
                    .build();

            httpClient = new OkHttpClient.Builder()
                    .sslSocketFactory(sslCtx.getSocketFactory(), trustManager)
                    .certificatePinner(pinner)
                    .connectTimeout(15, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .build();

            return httpClient;
        } catch (Exception e) {
            Log.e(TAG, "OkHttp init failed", e);
            throw new RuntimeException("HTTP client init failed", e);
        }
    }

    // ──────────────────────────────────────────────
    // 서버 공개키 획득 및 CryptoPipeline 초기화
    // ──────────────────────────────────────────────

    private synchronized ClientCryptoPipeline getCryptoPipeline() {
        if (cryptoPipeline != null) return cryptoPipeline;
        try {
            byte[] serverKey = fetchServerPublicKey();
            String deviceId = LogHandler.getAndroidID(context, context.getContentResolver());
            cryptoPipeline = new ClientCryptoPipeline(serverKey, deviceId);
            return cryptoPipeline;
        } catch (Exception e) {
            Log.e(TAG, "CryptoPipeline init failed", e);
            return null;
        }
    }

    private byte[] fetchServerPublicKey() throws Exception {
        if (cachedServerPublicKey != null) return cachedServerPublicKey;
        OkHttpClient client = getHttpClient();
        Request req = new Request.Builder()
                .url(BASE_URL + SERVERKEY_PATH)
                .get()
                .build();
        try (Response resp = client.newCall(req).execute()) {
            if (!resp.isSuccessful() || resp.body() == null) {
                throw new RuntimeException("Server key fetch failed: " + resp.code());
            }
            String b64 = resp.body().string().trim();
            cachedServerPublicKey = Base64.decode(b64, Base64.NO_WRAP);
            return cachedServerPublicKey;
        }
    }

    // ──────────────────────────────────────────────
    // 핵심 업로드 메서드
    // ──────────────────────────────────────────────

    /**
     * 로그 내용을 암호화하여 서버로 업로드.
     * 실패 시 SQLCipher 오프라인 큐에 저장하고 WorkManager 재시도 예약.
     */
    public void sendLogAsync(String deviceId, String logType,
                              String logContent, String chainHash,
                              FileTransferCallback callback) {
        new Thread(() -> {
            boolean success = false;
            try {
                success = uploadEncryptedLog(deviceId, logType, logContent, chainHash);
            } catch (Exception e) {
                Log.e(TAG, "Upload error, queuing offline", e);
            }
            if (success) {
                if (callback != null) callback.onSuccess();
            } else {
                queueOffline(deviceId, logType, logContent, chainHash);
                UploadQueueWorker.scheduleFlush(context);
                if (callback != null) callback.onFailure();
            }
        }).start();
    }

    /**
     * 동기 업로드 (WorkManager Worker에서 호출).
     * @return 성공 여부
     */
    public boolean uploadEncryptedLog(String deviceId, String logType,
                                       String logContent, String chainHash) {
        byte[] packetBytes = null;
        try {
            ClientCryptoPipeline pipeline = getCryptoPipeline();
            if (pipeline == null) return false;

            // 1. 암호화 파이프라인 (GZIP + ECDH + AES-GCM + ECDSA)
            packetBytes = pipeline.encrypt(logContent);

            // 2. 멀티파트 업로드 (logFile=암호화 패킷, hashFile=chain hash)
            String filename = deviceId + "_" + logType + ".enc";
            RequestBody logBody = RequestBody.create(packetBytes,
                    MediaType.parse("application/octet-stream"));
            RequestBody hashBody = RequestBody.create(chainHash.getBytes(),
                    MediaType.parse("text/plain"));

            RequestBody multipart = new MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart("logFile", filename, logBody)
                    .addFormDataPart("hashFile", deviceId + "_" + logType + "_hash.txt", hashBody)
                    .build();

            Request req = new Request.Builder()
                    .url(BASE_URL + UPLOAD_PATH)
                    .post(multipart)
                    .build();

            try (Response resp = getHttpClient().newCall(req).execute()) {
                Log.d(TAG, "Upload response: " + resp.code());
                return resp.isSuccessful();
            }
        } catch (Exception e) {
            Log.e(TAG, "uploadEncryptedLog failed", e);
            return false;
        } finally {
            if (packetBytes != null) Arrays.fill(packetBytes, (byte) 0);
        }
    }

    // ──────────────────────────────────────────────
    // 오프라인 큐 저장
    // ──────────────────────────────────────────────

    private void queueOffline(String deviceId, String logType,
                               String logContent, String chainHash) {
        try {
            String encrypted = CryptoManager.getInstance().encryptString(logContent);
            OfflineLogEntity entity = new OfflineLogEntity(deviceId, logType, encrypted, chainHash);
            OfflineLogDatabase.getInstance(context).offlineLogDao().insert(entity);
            Log.d(TAG, "Queued offline: " + logType);
        } catch (Exception e) {
            Log.e(TAG, "Offline queue insert failed", e);
        }
    }

    // ──────────────────────────────────────────────
    // 기존 파일 기반 전송 (하위 호환 - LogHandler 호출용)
    // ──────────────────────────────────────────────

    public void sendFilesAsync(java.io.File logFile, java.io.File hashFile,
                                FileTransferCallback callback) {
        new Thread(() -> {
            boolean success = false;
            try {
                String deviceId = LogHandler.getAndroidID(context, context.getContentResolver());
                String filename = logFile.getName(); // e.g. deviceId_AntiForensicLog.txt
                String[] parts = filename.split("_", 2);
                String logType = parts.length > 1 ? parts[1].replace(".txt", "") : "Unknown";

                byte[] content = java.nio.file.Files.readAllBytes(logFile.toPath());
                String rawText = new String(content, java.nio.charset.StandardCharsets.UTF_8);
                Arrays.fill(content, (byte) 0);

                // at-rest 복호화: 각 라인은 CryptoManager.encryptString()으로 암호화되어 있음
                // 복호화하여 평문 로그를 복원
                StringBuilder plainBuilder = new StringBuilder();
                CryptoManager crypto = CryptoManager.getInstance();
                String[] lines = rawText.split("\\n");
                int validLines = 0;
                for (String line : lines) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) continue;
                    try {
                        String plainLine = crypto.decryptToString(trimmed);
                        plainBuilder.append(plainLine).append("\n");
                        validLines++;
                    } catch (Exception decryptEx) {
                        // 복호화 실패 시 해당 라인은 이미 평문이거나 손상됨 → 그대로 포함
                        Log.w(TAG, "Line decryption failed, using as-is: " + decryptEx.getMessage());
                        plainBuilder.append(trimmed).append("\n");
                        validLines++;
                    }
                }

                if (validLines == 0) {
                    Log.w(TAG, "No valid log lines found in: " + filename);
                    callback.onFailure();
                    return;
                }

                String plainLogText = plainBuilder.toString();

                // 서버의 해시 계산 방식과 동일하게:
                // sanitizedContent = lines.split("\\r?\\n").joining("\n") → 마지막 \n 없음
                // 따라서 plainLogText의 trailing newline을 제거 후 해시 계산
                String sanitizedForHash = plainLogText.replaceAll("\\r?\\n$", "");

                // 복원된 평문에 대한 SHA-256 해시를 서버와 동일한 방식으로 계산
                String chainHash;
                try {
                    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                    byte[] hashBytes = md.digest(sanitizedForHash.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    StringBuilder hexSb = new StringBuilder();
                    for (byte b : hashBytes) {
                        String hex = Integer.toHexString(0xff & b);
                        if (hex.length() == 1) hexSb.append('0');
                        hexSb.append(hex);
                    }
                    chainHash = hexSb.toString();
                } catch (Exception hashEx) {
                    Log.e(TAG, "Hash computation failed, falling back to file hash", hashEx);
                    byte[] hashContent = java.nio.file.Files.readAllBytes(hashFile.toPath());
                    chainHash = new String(hashContent, java.nio.charset.StandardCharsets.UTF_8).trim();
                    Arrays.fill(hashContent, (byte) 0);
                }

                Log.d(TAG, "sendFilesAsync: decrypted " + validLines + " lines, chainHash=" + chainHash.substring(0, Math.min(16, chainHash.length())) + "...");
                success = uploadEncryptedLog(deviceId, logType, sanitizedForHash, chainHash);
            } catch (Exception e) {
                Log.e(TAG, "sendFilesAsync error", e);
            }
            if (success) {
                callback.onSuccess();
            } else {
                callback.onFailure();
            }
        }).start();
    }

    // ──────────────────────────────────────────────
    // 서버 타임스탬프 (평문 GET, cleartext URL 사용 불가 → HTTPS)
    // ──────────────────────────────────────────────

    public static String getServerTimestamp() {
        final String[] result = {null};
        CountDownLatch latch = new CountDownLatch(1);

        new Thread(() -> {
            try {
                URL url = new URL(BASE_URL + TIMESTAMP_PATH);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    reader.close();
                    result[0] = sb.toString();
                }
            } catch (Exception e) {
                Log.e(TAG, "getServerTimestamp failed", e);
            } finally {
                latch.countDown();
            }
        }).start();

        try {
            latch.await(6, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
        return result[0];
    }

    public interface FileTransferCallback {
        void onSuccess();
        void onFailure();
    }
}
