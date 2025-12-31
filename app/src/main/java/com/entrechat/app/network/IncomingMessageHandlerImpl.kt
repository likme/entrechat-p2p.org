/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Base64
import com.entrechat.app.config.LimitsConfig
import com.entrechat.app.config.ProtocolConfig
import com.entrechat.app.crypto.CryptoService
import com.entrechat.app.db.ContactEntity
import com.entrechat.app.db.IdentityEntity
import com.entrechat.app.db.ContactDao
import fi.iki.elonen.NanoHTTPD
import org.json.JSONObject


/**
 * Validates, decrypts (OpenPGP), and stores inbound messages.
 *
 * Security goals:
 * - Reject malformed envelopes early.
 * - Enforce replay protection (nonce-based).
 * - Reject debug plaintext unless the app is debuggable AND the message is a local self-test.
 * - Avoid logging or returning sensitive payloads.
 *
 * Protocol goals (v1):
 * - Inner JSON `msg_id` must match the outer envelope `msg_id`.
 * - `conv_id` must be consistent with v1 storage rule (peer fingerprint).
 *
 * Storage goals (MVP):
 * - Persist the inbound message in Room via [MessageRepository].
 * - Keep stored payload format stable without requiring a schema migration.
 */
class IncomingMessageHandlerImpl(
    private val cryptoService: CryptoService,
    private val messageRepository: MessageRepository,
    private val replayProtection: ReplayProtection,
    private val identityProvider: () -> IdentityEntity?,
    private val contactDao: ContactDao,
    private val requireVerifiedInbound: Boolean,
    private val appContext: Context
) : IncomingMessageHandler {

    companion object {
        /** Allowed clock skew for created_at (future). */
        private const val MAX_FUTURE_SKEW_MS: Long = 5 * 60 * 1000L

        /** Hard cap for inbound msg_id length to prevent abuse. */
        private const val MAX_MSG_ID_CHARS = 128

        /** Hard cap for nonce length to prevent abuse. */
        private const val MAX_NONCE_CHARS = 256

        /** Hard cap for base64 payload field length (envelope size protection). */
        private const val MAX_PGP_B64_CHARS = 2 * LimitsConfig.MAX_HTTP_PAYLOAD_BYTES
    }

    override fun handleIncoming(envelope: JSONObject): IncomingMessageResult {
        val msgId = envelope.optString("msg_id", "").trim()
        if (msgId.isEmpty() || msgId.length > MAX_MSG_ID_CHARS) return reject("BAD_REQUEST")

        val senderFpCanon = envelope.optString("sender_fp", "").trim().uppercase()
        if (senderFpCanon.isEmpty()) return reject("BAD_REQUEST", msgId)

        val recipientFpCanon = envelope.optString("recipient_fp", "").trim().uppercase()
        if (recipientFpCanon.isEmpty()) return reject("BAD_REQUEST", msgId)

        val nonce = envelope.optString("nonce", "").trim()
        if (nonce.isEmpty() || nonce.length > MAX_NONCE_CHARS) return reject("BAD_REQUEST", msgId)

        val payloadB64 = envelope.optString("payload_pgp", "").trim()
        val debugPlaintext = envelope.optString("debug_plaintext", "").trim()

        if (payloadB64.isEmpty() && debugPlaintext.isEmpty()) return reject("BAD_REQUEST", msgId)
        if (payloadB64.length > MAX_PGP_B64_CHARS) return reject("PAYLOAD_TOO_LARGE", msgId)

        val createdAt = envelope.optLong("created_at", -1L)
        if (createdAt <= 0L) return reject("BAD_REQUEST", msgId)

        val now = System.currentTimeMillis()
        if (createdAt > now + MAX_FUTURE_SKEW_MS) return reject("CREATED_AT_IN_FUTURE", msgId)

        // 1) Recipient must match the active local identity.
        val selfFpCanon = identityProvider.invoke()
            ?.fingerprint
            ?.trim()
            ?.uppercase()
            .orEmpty()

        if (selfFpCanon.isEmpty()) {
            // Local identity missing or not loaded. Do not proceed.
            return rejectWithStatus(
                status = HttpStatuses.UNPROCESSABLE_ENTITY_422,
                code = "LOCAL_IDENTITY_MISSING",
                msgId = msgId
            )
        }

        if (recipientFpCanon != selfFpCanon) {
            // Not addressed to this device/identity.
            return rejectWithStatus(
                status = NanoHTTPD.Response.Status.UNAUTHORIZED,
                code = "RECIPIENT_NOT_SELF",
                msgId = msgId
            )
        }

        // 2) Allowlist only: sender must exist in contacts.
        val senderContact = contactDao.getByFingerprint(senderFpCanon)
        if (senderContact == null) {
            // Unknown senders are dropped with no storage.
            return rejectWithStatus(
                status = NanoHTTPD.Response.Status.FORBIDDEN,
                code = "SENDER_NOT_ALLOWED",
                msgId = msgId
            )
        }

        // Optional strict mode: only accept VERIFIED/pinned senders.
        if (requireVerifiedInbound && senderContact.trustLevel != ContactEntity.TRUST_VERIFIED) {
            return rejectWithStatus(
                status = NanoHTTPD.Response.Status.FORBIDDEN,
                code = "SENDER_NOT_VERIFIED",
                msgId = msgId
            )
        }


        // 3) Replay detection must be cheap and must happen before expensive crypto.
        // Do it after allowlist to avoid nonce-table DoS by random senders.
        if (!replayProtection.markIfNew(senderFpCanon, nonce)) {
            return rejectWithStatus(
                status = HttpStatuses.UNPROCESSABLE_ENTITY_422,
                code = "REPLAY_DETECTED",
                msgId = msgId
            )
        }



        val plaintext: JSONObject = if (debugPlaintext.isNotEmpty()) {
            // Debug plaintext is a strictly local self-test path.
            if (!isDebuggable()) {
                return IncomingMessageResult.Rejected(
                    httpCode = NanoHTTPD.Response.Status.NOT_FOUND,
                    errorCode = "NOT_FOUND",
                    msgId = msgId
                )
            }

            if (debugPlaintext.length > LimitsConfig.MAX_HTTP_PAYLOAD_BYTES) {
                return reject("PAYLOAD_TOO_LARGE", msgId)
            }

            // selfFpCanon already validated earlier.
            if (senderFpCanon != selfFpCanon || recipientFpCanon != selfFpCanon) {
                return rejectWithStatus(
                    status = HttpStatuses.UNPROCESSABLE_ENTITY_422,
                    code = "DEBUG_PLAINTEXT_NOT_ALLOWED",
                    msgId = msgId
                )
            }


            try {
                JSONObject(debugPlaintext)
            } catch (_: Exception) {
                return reject("INVALID_JSON", msgId)
            }
        } else {
            val cryptoResult = cryptoService.verifyAndDecryptEnvelope(
                senderFingerprint = senderFpCanon,
                recipientFingerprint = recipientFpCanon,
                payloadBase64 = payloadB64
            )

            if (!cryptoResult.success) {
                val status: NanoHTTPD.Response.IStatus =
                    if (cryptoResult.errorCode == "RECIPIENT_UNKNOWN") {
                        HttpStatuses.UNPROCESSABLE_ENTITY_422
                    } else {
                        NanoHTTPD.Response.Status.UNAUTHORIZED
                    }

                return IncomingMessageResult.Rejected(
                    httpCode = status,
                    errorCode = cryptoResult.errorCode,
                    msgId = msgId
                )
            }

            cryptoResult.plaintextJson ?: return reject("CRYPTO_ERROR", msgId)
        }

        if (plaintext.optInt("v", -1) != ProtocolConfig.VERSION) {
            return reject("UNSUPPORTED_VERSION", msgId)
        }

        val innerMsgId = plaintext.optString("msg_id", "").trim()
        if (innerMsgId.isEmpty() || innerMsgId != msgId) {
            return reject("MSG_ID_MISMATCH", msgId)
        }

        val convIdRaw = plaintext.optString("conv_id", "").trim()
        if (convIdRaw.isEmpty()) return reject("BAD_REQUEST", msgId)

        // v1 rule: stored convId must match the peer fingerprint for UI stability.
        // Enforce consistency: conv_id must match sender fingerprint.
        val convIdStore = senderFpCanon
        val convIdCanon = convIdRaw.trim().uppercase()
        if (convIdCanon != convIdStore) {
            return reject("CONV_ID_MISMATCH", msgId)
        }

        val type = plaintext.optString("type", ProtocolConfig.TYPE_MESSAGE).trim()

        if (type == ProtocolConfig.TYPE_ADDR_UPDATE) {
            // Only accept addr_update from allowlisted + VERIFIED contacts.
            // This is enforced earlier by inbound allowlist + requireVerifiedInbound.
            val newOnion = plaintext.optString("new_onion", "").trim()
            if (newOnion.isEmpty()) {
                return rejectWithStatus(HttpStatuses.UNPROCESSABLE_ENTITY_422, "ADDR_UPDATE_MISSING_NEW_ONION", msgId)
            }

            val applied = contactDao.applyInboundOnionUpdate(
                senderFp = senderFpCanon,
                newOnionRaw = newOnion
            )
            if (!applied) {
                // Sender disappeared from DB between checks. Treat as forbidden.
                return rejectWithStatus(NanoHTTPD.Response.Status.FORBIDDEN, "SENDER_NOT_ALLOWED", msgId)
            }

            // Do not store as a chat message. It is a control message.
            return IncomingMessageResult.Ok(msgId)
        }

        // Default: normal chat message
        // 4) Passive onion hint: lets the receiver learn about sender onion rotation.
        val senderOnionHint = plaintext.optString("sender_onion", "").trim()
        if (senderOnionHint.isNotBlank()) {
            // Same rule as addr_update: VERIFIED -> pending, UNVERIFIED -> overwrite.
            // If contact disappears, ignore quietly (no logs).
            runCatching {
                contactDao.applyInboundOnionUpdate(
                    senderFp = senderFpCanon,
                    newOnionRaw = senderOnionHint
                )
            }
        }

        val body = plaintext.optString("body", "")
        if (body.length > LimitsConfig.MAX_BODY_CHARS) {
            return reject("BODY_TOO_LARGE", msgId)
        }


        val storedCiphertext = packStoredCipherV1(
            pgpB64 = payloadB64,
            body = body
        )

        messageRepository.storeIncomingMessage(
            msgId = msgId,
            convId = convIdStore,
            senderFp = senderFpCanon,
            recipientFp = recipientFpCanon,
            createdAt = createdAt,
            ciphertextBase64 = storedCiphertext
        )

        return IncomingMessageResult.Ok(msgId)

    }

    /**
     * Packs stored payload into a single DB string field.
     *
     * Format:
     * - v1|pgp=<b64>|pt=<b64_json>
     * - json is {"body":"..."}
     *
     * Security:
     * - This includes message body content. It must never be exposed in release diagnostics.
     */
    private fun packStoredCipherV1(pgpB64: String, body: String): String {
        val pgp = pgpB64.trim()
        val ptJson = JSONObject(mapOf("body" to body)).toString()
        val ptB64 = Base64.encodeToString(ptJson.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        return "v1|pgp=$pgp|pt=$ptB64"
    }

    /**
     * Returns true when the app is debuggable (FLAG_DEBUGGABLE).
     * Used to gate debug-only functionality.
     */
    private fun isDebuggable(): Boolean {
        val flags = appContext.applicationInfo.flags
        return (flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    /**
     * Convenience for returning a rejection with a stable error code.
     * Never include sensitive details in responses.
     */
    private fun rejectWithStatus(
        status: NanoHTTPD.Response.IStatus,
        code: String,
        msgId: String? = null
    ): IncomingMessageResult.Rejected =
        IncomingMessageResult.Rejected(
            httpCode = status,
            errorCode = code,
            msgId = msgId
        )

    /**
     * Convenience for returning a 400 rejection with a stable error code.
     */
    private fun reject(code: String, msgId: String? = null): IncomingMessageResult.Rejected =
        rejectWithStatus(NanoHTTPD.Response.Status.BAD_REQUEST, code, msgId)
}

