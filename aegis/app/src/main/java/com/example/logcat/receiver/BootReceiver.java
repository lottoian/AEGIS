package com.example.logcat.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.example.logcat.queue.UploadQueueWorker;
import com.example.logcat.service.AntiForensicLogger;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent){

        if(Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())){
            Log.d("BootReceiver", "Device boot completed. Starting services.");
            Intent serviceIntent = new Intent(context, AntiForensicLogger.class);
            context.startForegroundService(serviceIntent);
            // 부팅 후 네트워크 연결 시 오프라인 큐 + .txt 플러시
            UploadQueueWorker.scheduleFlush(context);
        }
    }
}