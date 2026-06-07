package com.example.logcat.queue;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.Query;

import java.util.List;

@Dao
public interface OfflineLogDao {

    @Insert
    void insert(OfflineLogEntity entity);

    @Query("SELECT * FROM offline_log_queue ORDER BY created_at ASC")
    List<OfflineLogEntity> getAllPending();

    @Query("DELETE FROM offline_log_queue WHERE id = :id")
    void deleteById(long id);

    @Query("UPDATE offline_log_queue SET retry_count = retry_count + 1 WHERE id = :id")
    void incrementRetry(long id);

    @Query("SELECT COUNT(*) FROM offline_log_queue")
    int countPending();

    @Query("SELECT SUM(LENGTH(encrypted_log_content)) FROM offline_log_queue")
    long totalContentBytes();

    @Query("DELETE FROM offline_log_queue WHERE id IN (SELECT id FROM offline_log_queue ORDER BY created_at ASC LIMIT :n)")
    void deleteOldest(int n);
}
