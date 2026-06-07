package com.example.logcat.queue;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.example.logcat.manager.CryptoManager;
import com.example.logcat.manager.LogHandler;
import com.example.logcat.manager.ServerTransmitter;

import java.util.List;

/**
 * WorkManager Worker: 네트워크 복구 시 오프라인 큐를 서버로 플러시.
 * NetworkType.CONNECTED 제약으로 Wi-Fi/데이터 연결 시에만 실행.
 */
public class UploadQueueWorker extends Worker {

    private static final String TAG = "UploadQueueWorker";
    private static final int MAX_RETRIES = 5;

    public UploadQueueWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context ctx = getApplicationContext();
        OfflineLogDatabase db = OfflineLogDatabase.getInstance(ctx);
        OfflineLogDao dao = db.offlineLogDao();
        CryptoManager cm = CryptoManager.getInstance();
        ServerTransmitter transmitter = new ServerTransmitter(ctx);

        List<OfflineLogEntity> pending = dao.getAllPending();
        Log.d(TAG, "[FLUSH START] 네트워크 복구 감지 — 큐 항목: " + pending.size() + "개");

        boolean anyFailed = false;

        for (OfflineLogEntity entry : pending) {
            if (entry.retryCount >= MAX_RETRIES) {
                Log.w(TAG, "[FLUSH] MAX_RETRIES 초과, 삭제: id=" + entry.id + " type=" + entry.logType);
                dao.deleteById(entry.id);
                continue;
            }
            try {
                Log.d(TAG, "[FLUSH] 큐 항목 전송 시도: id=" + entry.id + " type=" + entry.logType + " retry=" + entry.retryCount);
                String logContent = cm.decryptToString(entry.encryptedLogContent);
                Log.d(TAG, "[FLUSH] 복호화 성공, 길이=" + logContent.length());

                String transmissionTs = ServerTransmitter.getServerTimestamp();
                if (transmissionTs != null) {
                    ServerTransmitter.saveServerTimestampCache(ctx, transmissionTs);
                    logContent = logContent + " ; transmissionTimestamp: " + transmissionTs;
                    Log.d(TAG, "[FLUSH] transmissionTimestamp 추가: " + transmissionTs);
                } else {
                    Log.w(TAG, "[FLUSH] transmissionTimestamp 획득 실패 (서버 미응답)");
                }

                boolean success = transmitter.uploadEncryptedLog(
                        entry.deviceId, entry.logType, logContent, entry.chainHash);

                if (success) {
                    dao.deleteById(entry.id);
                    LogHandler.clearLogFileStatic(ctx, entry.deviceId, entry.logType);
                    Log.d(TAG, "[FLUSH] 전송 성공: id=" + entry.id + " type=" + entry.logType);
                } else {
                    dao.incrementRetry(entry.id);
                    anyFailed = true;
                    Log.w(TAG, "[FLUSH] 전송 실패: id=" + entry.id + " retry=" + (entry.retryCount + 1));
                }
            } catch (Exception e) {
                Log.e(TAG, "[FLUSH] 예외 발생: id=" + entry.id, e);
                dao.incrementRetry(entry.id);
                anyFailed = true;
            }
        }

        // 큐 플러시 후, 오프라인 중 .txt에 쌓인 내용도 전송 (트리거 미발생 분)
        Log.d(TAG, "[FLUSH] .txt 파일 스캔 시작 (트리거 미발생 분)");
        boolean txtFailed = LogHandler.sendAllPendingTxt(ctx, transmitter);
        anyFailed = anyFailed || txtFailed;
        Log.d(TAG, "[FLUSH END] 완료 — anyFailed=" + anyFailed);

        return anyFailed ? Result.retry() : Result.success();
    }

    /** 앱 시작/네트워크 복구 시 호출하여 플러시 작업 예약. */
    public static void scheduleFlush(Context ctx) {
        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build();

        OneTimeWorkRequest request = new OneTimeWorkRequest.Builder(UploadQueueWorker.class)
                .setConstraints(constraints)
                .build();

        WorkManager.getInstance(ctx)
                .enqueueUniqueWork("aegis_offline_flush",
                        androidx.work.ExistingWorkPolicy.KEEP, request);

        Log.d(TAG, "Offline flush work scheduled.");
    }
}
