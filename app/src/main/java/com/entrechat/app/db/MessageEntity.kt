/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Persistent representation of a chat message.
 *
 * Stores transport-level data (ciphertext) and minimal UI-related metadata
 * (status, timestamps, retry bookkeeping). Cryptographic verification is
 * performed outside the database layer.
 *
 * Security notes:
 * - The database must never be treated as a trusted source of plaintext.
 * - [ciphertextBase64] is the authoritative payload for cryptographic operations.
 * - [body] is optional and intended for UI convenience only (MVP), not for security decisions.
 * - UI must never display [ciphertextBase64].
 */
@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["convId"]),
        Index(value = ["createdAt"]),
        Index(value = ["serverReceivedAt"]),
        Index(value = ["senderFp"]),
        Index(value = ["recipientFp"]),
        Index(value = ["status"]),
        Index(value = ["nextRetryAt"])
    ]
)
data class MessageEntity(

    /** Globally unique message identifier (idempotence key). */
    @PrimaryKey
    val msgId: String,

    /** Stable conversation identifier derived from participants. */
    val convId: String,

    /** Message direction relative to the local user. Expected values: "IN" | "OUT". */
    val direction: String,

    /** Fingerprint of the sender public key. */
    val senderFp: String,

    /** Fingerprint of the recipient public key. */
    val recipientFp: String,

    /** Local creation timestamp (milliseconds since epoch). */
    val createdAt: Long,

    /**
     * Ciphertext payload encoded as Base64.
     *
     * This field may contain:
     * - OpenPGP-encrypted payloads
     * - Structured containers (e.g. v1|pgp=...|pt=...)
     *
     * Must never be logged or modified in-place.
     */
    val ciphertextBase64: String,

    /**
     * Optional plaintext body extracted for UI rendering.
     *
     * This value is derived after successful decryption and verification.
     * It is not authoritative and may be null.
     *
     * IMPORTANT:
     * - Do not store placeholders like "(encrypted)" here.
     * - On decrypt/verify failure, keep this null.
     */
    val body: String? = null,

    /** MIME type associated with [body]. Defaults to plain text. */
    val bodyMime: String? = "text/plain",

    /**
     * Delivery status of the message.
     *
     * Allowed values (MVP):
     * - "QUEUED"   outgoing pending / retry scheduled
     * - "SENT"     sent from this device (does not guarantee remote receipt)
     * - "FAILED"   temporarily paused; user can retry
     * - "RECEIVED" incoming received
     *
     * Transitions must be controlled by higher layers.
     */
    val status: String,

    /** Number of send attempts for outgoing messages. */
    val attemptCount: Int = 0,

    /**
     * Last error category (short code), for diagnostics and optional UI details.
     * Examples: "TIMEOUT", "TOR_NOT_READY", "HTTP_503", "BAD_REQUEST".
     */
    val lastError: String? = null,

    /**
     * Timestamp (ms since epoch) after which an automatic retry is allowed.
     * 0 means "no schedule / retry ASAP when triggered".
     */
    val nextRetryAt: Long = 0L,

    /**
     * Updated when status/body/retry metadata changes.
     * Helps RecyclerView diffing even if ordering timestamps don't change.
     */
    val updatedAt: Long = createdAt,

    /**
     * Timestamp set when the message is received from the remote peer.
     *
     * For outgoing messages or pending deliveries, this value may be 0.
     * UI ordering should fall back to [createdAt] when this is unset.
     */
    val serverReceivedAt: Long
) {

    /**
     * UI-safe message text.
     *
     * Rules:
     * - Never expose ciphertext.
     * - Treat blank or placeholder bodies as "not decrypted".
     * - Return a neutral placeholder for UI rendering.
     */
    fun uiBodyOrPlaceholder(): String {
        val t = body?.trim().orEmpty()
        if (t.isBlank()) return "(encrypted)"
        if (t.equals("(encrypted)", ignoreCase = true)) return "(encrypted)"
        return t
    }

    /**
     * True if UI can render plaintext content.
     */
    fun isDecryptedForUi(): Boolean {
        val t = body?.trim().orEmpty()
        return t.isNotBlank() && !t.equals("(encrypted)", ignoreCase = true)
    }
}
