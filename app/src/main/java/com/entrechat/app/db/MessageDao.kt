/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for [MessageEntity].
 *
 * Performance notes:
 * - Conversation listing is a hot path. Queries are written to be index-friendly and stable.
 *
 * Reliability notes:
 * - [insert] uses IGNORE to provide idempotence on [MessageEntity.msgId].
 *
 * Threading notes:
 * - All methods are `suspend` to prevent accidental database IO on the main thread.
 */
@Dao
interface MessageDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: MessageEntity): Long

    @Query("SELECT EXISTS(SELECT 1 FROM messages WHERE msgId = :msgId)")
    suspend fun existsByMsgId(msgId: String): Boolean

    @Query("DELETE FROM messages WHERE convId = :convId")
    suspend fun deleteByConvId(convId: String)

    @Query("DELETE FROM messages")
    suspend fun deleteAll()

    @Query(
        """
        SELECT * FROM messages
        WHERE (:convId IS NULL OR convId = :convId)
        ORDER BY
          CASE WHEN serverReceivedAt = 0 THEN createdAt ELSE serverReceivedAt END DESC,
          createdAt DESC
        LIMIT :limit
        """
    )
    suspend fun list(convId: String?, limit: Int): List<MessageEntity>

    /**
     * Basic status update (kept for callers that don't care about retry metadata).
     * Prefer [updateStatusWithMeta] for outgoing messages.
     */
    @Query(
        """
        UPDATE messages
        SET status = :status,
            updatedAt = :updatedAt
        WHERE msgId = :msgId
        """
    )
    suspend fun updateStatus(msgId: String, status: String, updatedAt: Long = System.currentTimeMillis())

    /**
     * Status update with diagnostics metadata.
     * Use for FAILED transitions to store [lastError].
     */
    @Query(
        """
        UPDATE messages
        SET status = :status,
            lastError = :lastError,
            updatedAt = :updatedAt
        WHERE msgId = :msgId
        """
    )
    suspend fun updateStatusWithMeta(
        msgId: String,
        status: String,
        lastError: String?,
        updatedAt: Long
    )

    /**
     * Marks a message as queued and schedules an automatic retry.
     * - Increments [attemptCount]
     * - Clears [lastError]
     */
    @Query(
        """
        UPDATE messages
        SET status = 'QUEUED',
            attemptCount = attemptCount + 1,
            nextRetryAt = :nextRetryAt,
            lastError = NULL,
            updatedAt = :updatedAt
        WHERE msgId = :msgId
        """
    )
    suspend fun markRetryScheduled(
        msgId: String,
        nextRetryAt: Long,
        updatedAt: Long
    )

    /**
     * Resets a failed message back to QUEUED for an immediate manual retry.
     * Does not increment [attemptCount] here; do it when actually attempting send
     * (or keep it here if that's simpler in your sender).
     */
    @Query(
        """
        UPDATE messages
        SET status = 'QUEUED',
            nextRetryAt = 0,
            lastError = NULL,
            updatedAt = :updatedAt
        WHERE msgId = :msgId AND status = 'FAILED'
        """
    )
    suspend fun markManualRetry(msgId: String, updatedAt: Long): Int

    /**
     * Batch retry: convert all FAILED outgoing messages for a conversation to QUEUED.
     */
    @Query(
        """
        UPDATE messages
        SET status = 'QUEUED',
            nextRetryAt = 0,
            lastError = NULL,
            updatedAt = :updatedAt
        WHERE convId = :convId
          AND direction = 'OUT'
          AND status = 'FAILED'
        """
    )
    suspend fun retryAllFailed(convId: String, updatedAt: Long): Int

    /**
     * Lists outgoing messages eligible for retry.
     * Eligibility:
     * - status FAILED or QUEUED
     * - nextRetryAt == 0 (ASAP) OR nextRetryAt <= now
     *
     * Caller decides whether to retry automatically (Tor READY / foreground / timer).
     */
    @Query(
        """
        SELECT * FROM messages
        WHERE convId = :convId
          AND direction = 'OUT'
          AND status IN ('FAILED', 'QUEUED')
          AND (nextRetryAt = 0 OR nextRetryAt <= :now)
        ORDER BY createdAt ASC
        LIMIT :limit
        """
    )
    suspend fun listRetryCandidates(convId: String, now: Long, limit: Int): List<MessageEntity>

    @Query(
        """
        UPDATE messages
        SET body = :body,
            bodyMime = :mime,
            updatedAt = :updatedAt
        WHERE msgId = :msgId
        """
    )
    suspend fun updateBody(
        msgId: String,
        body: String?,
        mime: String? = "text/plain",
        updatedAt: Long = System.currentTimeMillis()
    )

    @Query(
        """
        SELECT * FROM messages
        WHERE convId = :convId
        ORDER BY
          CASE WHEN serverReceivedAt = 0 THEN createdAt ELSE serverReceivedAt END ASC,
          createdAt ASC
        LIMIT :limit
        """
    )
    fun observeConversation(convId: String, limit: Int): Flow<List<MessageEntity>>
}
