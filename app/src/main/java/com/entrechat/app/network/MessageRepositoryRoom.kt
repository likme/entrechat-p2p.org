/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import com.entrechat.app.db.MessageDao
import com.entrechat.app.db.MessageEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * Room-backed implementation of [MessageRepository].
 *
 * Note:
 * - This repository exposes synchronous methods for simplicity.
 * - The underlying DAO is suspend. Calls are bridged using runBlocking(Dispatchers.IO)
 *   to keep call sites unchanged.
 *
 * Status contract:
 * - QUEUED: temporary unsent, eligible for retry.
 * - SENT_HTTP_OK: sent successfully.
 * - FAILED: terminal failure (or expired deadline).
 */
class MessageRepositoryRoom(
    private val messageDao: MessageDao
) : MessageRepository {

    override fun storeIncomingMessage(
        msgId: String,
        convId: String,
        senderFp: String,
        recipientFp: String,
        createdAt: Long,
        ciphertextBase64: String
    ) {
        val now = System.currentTimeMillis()
        runBlocking(Dispatchers.IO) {
            messageDao.insert(
                MessageEntity(
                    msgId = msgId,
                    convId = convId,
                    direction = "IN",
                    senderFp = senderFp,
                    recipientFp = recipientFp,
                    createdAt = createdAt,
                    ciphertextBase64 = ciphertextBase64,
                    status = "RECEIVED",
                    serverReceivedAt = now
                )
            )
        }
    }

    /**
     * OUT uses a different DB id to avoid collisions with IN (same protocol msgId).
     */
    fun outDbId(msgId: String): String = "OUT:$msgId"

    fun storeOutgoingQueued(
        msgId: String,
        convId: String,
        senderFp: String,
        recipientFp: String,
        createdAt: Long,
        ciphertextBase64: String
    ) {
        val now = System.currentTimeMillis()
        runBlocking(Dispatchers.IO) {
            messageDao.insert(
                MessageEntity(
                    msgId = outDbId(msgId),
                    convId = convId,
                    direction = "OUT",
                    senderFp = senderFp,
                    recipientFp = recipientFp,
                    createdAt = createdAt,
                    ciphertextBase64 = ciphertextBase64,
                    status = "QUEUED",
                    serverReceivedAt = now
                )
            )
        }
    }

    fun markOutgoingSentOk(msgId: String) {
        runBlocking(Dispatchers.IO) {
            messageDao.updateStatus(outDbId(msgId), "SENT_HTTP_OK")
        }
    }

    /**
     * Mark as QUEUED (retryable). Use this for transient failures:
     * - Tor not ready
     * - Tor client null
     * - Local server not ready
     * - HTTP/network failure
     */
    fun markOutgoingQueued(msgId: String) {
        runBlocking(Dispatchers.IO) {
            messageDao.updateStatus(outDbId(msgId), "QUEUED")
        }
    }

    /**
     * Mark as FAILED (terminal). Use this only for:
     * - invalid address format
     * - blocked direct HTTP in release
     * - crypto failures (if you choose to store message at all)
     * - expired deadline (to be added later)
     */
    fun markOutgoingFailed(msgId: String) {
        runBlocking(Dispatchers.IO) {
            messageDao.updateStatus(outDbId(msgId), "FAILED")
        }
    }

    fun list(convId: String?, limit: Int): List<MessageEntity> {
        val safeLimit = limit.coerceIn(1, 500)
        return runBlocking(Dispatchers.IO) {
            messageDao.list(convId, safeLimit)
        }
    }
}
