/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Base64
import android.util.Log
import com.entrechat.app.config.LimitsConfig
import com.entrechat.app.config.ProtocolConfig
import com.entrechat.app.crypto.CryptoService
import com.entrechat.app.db.ContactDao
import com.entrechat.app.db.IdentityEntity
import com.entrechat.app.db.ContactEntity
import com.entrechat.app.tor.TorManager
import com.entrechat.app.tor.TorState
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID



class OutgoingMessageSender(
    private val appContext: Context,
    private val identityProvider: () -> IdentityEntity?,
    private val cryptoService: CryptoService,
    private val localHttpClient: LocalHttpJsonClient,
    private val remoteMessageClientDirect: RemoteMessageClient,
    remoteMessageClientTor: RemoteMessageClient?,
    private val torManager: TorManager,
    private val contactDao: ContactDao,
    private val messageRepo: MessageRepositoryRoom? = null,
    private val localServerBaseUrlProvider: () -> String? = { null }
) {

    companion object {
        private const val TAG = "OutgoingMessageSender"
        private const val FP_HEX_LEN = 40
        private const val NONCE_BYTES = 18

        // Base64 expands ~4/3. Use a safe headroom factor.
        private const val MAX_PGP_B64_CHARS = (LimitsConfig.MAX_HTTP_PAYLOAD_BYTES * 2)

        // Tor v3 onion host is 56 base32 chars + ".onion"
        private val ONION_V3_HOST_RE = Regex("^[a-z2-7]{56}\\.onion\$", RegexOption.IGNORE_CASE)
        private val HOST_PORT_RE = Regex("^([^:]+)(?::(\\d{1,5}))?\$")
    }

    @Volatile private var torClient: RemoteMessageClient? = remoteMessageClientTor
    private val rng = SecureRandom()

    @Synchronized fun attachTorClient(client: RemoteMessageClient?) {
        Log.i(TAG, "attachTorClient sender@${System.identityHashCode(this)} client=${client?.let { it::class.java.simpleName + "@" + System.identityHashCode(it) }}")
        torClient = client
    }
    @Synchronized fun detachTorClient() {
        Log.w(TAG, "detachTorClient sender@${System.identityHashCode(this)} was=${torClient?.let { it::class.java.simpleName + "@" + System.identityHashCode(it) }}")
        torClient = null
    }


    sealed class SendResult {
        data class Sent(val msgId: String) : SendResult()

        // Retryable (DB must stay QUEUED)
        data class QueuedLocalNotReady(val msgId: String) : SendResult()
        data class QueuedTorNotReady(val msgId: String) : SendResult()
        data class QueuedHttpFail(val msgId: String, val httpCode: Int) : SendResult()

        // Terminal (DB must be FAILED)
        data class FailedMissingAddress(val msgId: String) : SendResult()
        data class FailedBadAddress(val msgId: String) : SendResult()
        data class FailedBlockedDirectHttp(val msgId: String) : SendResult()
        data class FailedCryptoError(val msgId: String) : SendResult()

        // TrustLevel
        data class FailedContactNotVerified(val msgId: String) : SendResult()

    }

    fun send(toFpRaw: String, body: String): SendResult {
        val id = identityProvider.invoke() ?: throw IllegalStateException("NO_IDENTITY")
        val selfFp = canonFpOrThrow(id.fingerprint, "SELF_FP_INVALID")
        val toFp = canonFpOrThrow(toFpRaw, "TO_FP_INVALID")
        return if (toFp == selfFp) sendSelf(selfFp, body) else sendRemote(selfFp, toFp, body)
    }

    /**
     * Sends a signed+encrypted address update to a VERIFIED contact.
     *
     * This uses the existing v1 envelope transport and crypto pipeline.
     * Receiver must treat onion as mutable and fingerprint as identity root.
     */
    fun sendAddressUpdate(toFpRaw: String, newOnionRaw: String): SendResult {
        val id = identityProvider.invoke() ?: throw IllegalStateException("NO_IDENTITY")
        val selfFp = canonFpOrThrow(id.fingerprint, "SELF_FP_INVALID")
        val toFp = canonFpOrThrow(toFpRaw, "TO_FP_INVALID")

        val contact = contactDao.getByFingerprint(toFp) ?: throw IllegalStateException("UNKNOWN_CONTACT")
        if (contact.trustLevel != ContactEntity.TRUST_VERIFIED) {
            val msgId = UUID.randomUUID().toString()
            Log.w(TAG, "sendAddressUpdate blocked: contact not verified to=${fpTag(toFp)} msg=${msgId.take(8)}")
            return SendResult.FailedContactNotVerified(msgId)
        }

        val normalizedNew = normalizeRemoteAddress(newOnionRaw)
        if (normalizedNew.terminalReason != null || !normalizedNew.isOnion) {
            val msgId = UUID.randomUUID().toString()
            Log.w(TAG, "sendAddressUpdate failed: bad new onion to=${fpTag(toFp)} msg=${msgId.take(8)}")
            return SendResult.FailedBadAddress(msgId)
        }

        val msgId = UUID.randomUUID().toString()
        val createdAt = System.currentTimeMillis()
        val nonce = newNonce()
        val tsSec = createdAt / 1000L

        val oldOnion = contact.onion

        // IMPORTANT: receiver currently enforces conv_id == sender_fp
        val (innerBytes, _) = buildInnerAddrUpdateV1Bytes(
            msgId = msgId,
            senderFp = selfFp,
            recipientFp = toFp,
            convId = selfFp,
            newOnion = newOnionRaw.trim(),
            oldOnion = oldOnion,
            tsSec = tsSec,
            nonce = nonce
        )

        val encRes = cryptoService.encryptAndSignEnvelope(
            senderFingerprint = selfFp,
            recipientFingerprint = toFp,
            plaintextJsonUtf8 = innerBytes
        )
        if (!encRes.success) {
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = toFp,
                senderFp = selfFp,
                recipientFp = toFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            Log.w(TAG, "sendAddressUpdate failed: crypto error to=${fpTag(toFp)} msg=${msgId.take(8)} code=${encRes.errorCode}")
            return SendResult.FailedCryptoError(msgId)
        }

        val payloadB64 = encRes.plaintextJson?.optString("payload_pgp", "").orEmpty()
        val payloadB64Clean = payloadB64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        if (payloadB64Clean.isBlank() || payloadB64Clean.length > MAX_PGP_B64_CHARS) {
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = toFp,
                senderFp = selfFp,
                recipientFp = toFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            return SendResult.FailedCryptoError(msgId)
        }

        // Store first, then send (same semantics as normal sendRemote).
        messageRepo?.storeOutgoingQueued(
            msgId = msgId,
            convId = toFp,
            senderFp = selfFp,
            recipientFp = toFp,
            createdAt = createdAt,
            ciphertextBase64 = packStoredCipher(payloadB64Clean)
        )

        val normalizedPeer = normalizeRemoteAddress(contact.onion)
        if (normalizedPeer.terminalReason != null) {
            messageRepo?.markOutgoingFailed(msgId)
            return when (normalizedPeer.terminalReason) {
                TerminalAddrReason.MISSING -> SendResult.FailedMissingAddress(msgId)
                TerminalAddrReason.BAD_FORMAT,
                TerminalAddrReason.AMBIGUOUS -> SendResult.FailedBadAddress(msgId)
            }
        }

        val client = synchronized(this) { torClient }
        if (normalizedPeer.isOnion && client == null) {
            messageRepo?.markOutgoingQueued(msgId)
            return SendResult.QueuedTorNotReady(msgId)
        }

        val baseUrl = normalizedPeer.baseUrl
        val useClient = if (normalizedPeer.isOnion) client!! else remoteMessageClientDirect

        val envelopeStr = buildEnvelopeV1(
            type = ProtocolConfig.TYPE_ADDR_UPDATE,
            msgId = msgId,
            senderFp = selfFp,
            recipientFp = toFp,
            createdAt = createdAt,
            nonce = nonce,
            payloadB64 = payloadB64Clean
        )

        val host = hostTag(baseUrl)
        Log.i(TAG, "sendAddressUpdate envelope msg=${msgId.take(8)} to=${fpTag(toFp)} host=$host")

        val res = useClient.postMessage(baseUrl, envelopeStr)
        if (!res.ok) {
            messageRepo?.markOutgoingQueued(msgId)
            return SendResult.QueuedHttpFail(msgId, res.httpCode)
        }

        messageRepo?.markOutgoingSentOk(msgId)
        return SendResult.Sent(msgId)
    }


    /**
     * Local encrypted “Note to self”, like Signal.
     *
     * Security:
     * - No network. No Tor. No HTTP.
     * - OpenPGP encrypted+signed to self.
     * - DB stores ciphertext only (pgp=). No plaintext (pt=).
     * - convId is the local identity fingerprint.
     */
    fun sendNoteToSelf(body: String): SendResult {
        requireValidBody(body)

        val id = identityProvider.invoke() ?: throw IllegalStateException("NO_IDENTITY")
        val selfFp = canonFpOrThrow(id.fingerprint, "SELF_FP_INVALID")

        val msgId = UUID.randomUUID().toString()
        val createdAt = System.currentTimeMillis()

        val (innerBytes) = buildInnerV1Bytes(
            msgId = msgId,
            senderFp = selfFp,
            body = body,
            convId = selfFp // convId = local identity fp
        )

        val encRes = cryptoService.encryptAndSignEnvelope(
            senderFingerprint = selfFp,
            recipientFingerprint = selfFp,
            plaintextJsonUtf8 = innerBytes
        )

        if (!encRes.success) {
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = selfFp,
                senderFp = selfFp,
                recipientFp = selfFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            Log.w(TAG, "sendNoteToSelf failed: crypto error msg=${msgId.take(8)} code=${encRes.errorCode}")
            return SendResult.FailedCryptoError(msgId)
        }

        val payloadB64 = encRes.plaintextJson?.optString("payload_pgp", "").orEmpty()


        val payloadB64Clean = payloadB64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        if (payloadB64Clean.isBlank() || payloadB64Clean.length > MAX_PGP_B64_CHARS) {
            Log.w(TAG, "sendX failed: bad payload msg=${msgId.take(8)} len=${payloadB64Clean.length}")
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = selfFp,
                senderFp = selfFp,
                recipientFp = selfFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            return SendResult.FailedCryptoError(msgId)
        }


        // Store then mark as SENT_OK immediately (no network hop).
        messageRepo?.storeOutgoingQueued(
            msgId = msgId,
            convId = selfFp,
            senderFp = selfFp,
            recipientFp = selfFp,
            createdAt = createdAt,
            ciphertextBase64 = packStoredCipher(payloadB64Clean)
        )
        messageRepo?.markOutgoingSentOk(msgId)

        Log.i(TAG, "sendNoteToSelf ok msg=${msgId.take(8)}")
        return SendResult.Sent(msgId)
    }

    private fun isDebuggable(): Boolean {
        val flags = appContext.applicationInfo.flags
        return (flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    private fun requireValidBody(body: String) {
        if (body.isBlank()) throw IllegalArgumentException("EMPTY_BODY")
        if (body.length > LimitsConfig.MAX_BODY_CHARS) throw IllegalArgumentException("BODY_TOO_LARGE")
    }

    private fun canonFpOrThrow(fpRaw: String?, err: String): String {
        val fp = (fpRaw ?: "").trim().uppercase()
        if (fp.isEmpty()) throw IllegalArgumentException(err)
        if (fp.length != FP_HEX_LEN || fp.any { it !in "0123456789ABCDEF" }) {
            throw IllegalArgumentException(err)
        }
        return fp
    }

    private fun newNonce(): String {
        val b = ByteArray(NONCE_BYTES)
        rng.nextBytes(b)
        return Base64.encodeToString(b, Base64.NO_WRAP)
            .replace('+', '-')
            .replace('/', '_')
            .trimEnd('=')
    }

    private fun fpTag(fp: String) = fp.take(12)
    private fun hostTag(h: String) = h.take(16)

    private fun buildInnerV1Bytes(
        msgId: String,
        senderFp: String,
        body: String,
        convId: String,
        senderOnionHint: String? = null
    ): Pair<ByteArray, JSONObject> {
        val base = mutableMapOf(
            "v" to ProtocolConfig.VERSION,
            "msg_id" to msgId,
            "conv_id" to convId,
            "body" to body
        )

        val hint = senderOnionHint?.trim().orEmpty()
        if (hint.isNotBlank()) {
            // Transport hint only. Signed+encrypted with the message.
            base["sender_onion"] = hint
        }

        val innerObj = JSONObject(base)
        return innerObj.toString().toByteArray(Charsets.UTF_8) to innerObj
    }


    private fun buildInnerAddrUpdateV1Bytes(
        msgId: String,
        senderFp: String,
        recipientFp: String,
        convId: String,
        newOnion: String,
        oldOnion: String?,
        tsSec: Long,
        nonce: String
    ): Pair<ByteArray, JSONObject> {
        val innerObj = JSONObject(
            mapOf(
                "v" to ProtocolConfig.VERSION,
                "type" to ProtocolConfig.TYPE_ADDR_UPDATE,
                "msg_id" to msgId,
                "sender_fp" to senderFp,
                "recipient_fp" to recipientFp,
                "conv_id" to convId,
                "ts" to tsSec,
                "nonce" to nonce,
                "new_onion" to newOnion
            )
        )
        if (!oldOnion.isNullOrBlank()) innerObj.put("old_onion", oldOnion)
        return innerObj.toString().toByteArray(Charsets.UTF_8) to innerObj
    }


    private fun buildEnvelopeV1(
        type: String,
        msgId: String,
        senderFp: String,
        recipientFp: String,
        createdAt: Long,
        nonce: String,
        payloadB64: String
    ): String {
        val env = JSONObject(
            mapOf(
                "v" to ProtocolConfig.VERSION,
                "type" to type,
                "msg_id" to msgId,
                "sender_fp" to senderFp,
                "recipient_fp" to recipientFp,
                "created_at" to createdAt,
                "nonce" to nonce,
                "payload_pgp" to payloadB64
            )
        )
        return env.toString()
    }


    /**
     * Outbound Tor sends require SOCKS/bootstrap readiness.
     * Do not gate on local hidden service publication.
     */
    private fun isTorClientReady(): Boolean {
        return when (torManager.state.value) {
            is TorState.Ready -> true
            else -> false
        }
    }

    private data class NormalizedAddress(
        val isOnion: Boolean,
        val baseUrl: String,
        val terminalReason: TerminalAddrReason? = null
    )

    private enum class TerminalAddrReason {
        MISSING,
        BAD_FORMAT,
        AMBIGUOUS
    }

    /**
     * Accept:
     * - xxxx.onion
     * - xxxx.onion:port
     * - http(s)://host
     * - http(s)://host:port
     *
     * Reject:
     * - any path/query/fragment (ambiguous for a baseUrl API client)
     * - non-onion without scheme (ambiguous)
     */
    private fun normalizeRemoteAddress(raw: String?): NormalizedAddress {
        val s = (raw ?: "").trim()
        if (s.isBlank()) return NormalizedAddress(false, "", TerminalAddrReason.MISSING)

        // Explicit URL
        if (s.startsWith("http://", true) || s.startsWith("https://", true)) {
            return try {
                val uri = java.net.URI(s)
                val scheme = (uri.scheme ?: "").lowercase()
                val host = (uri.host ?: "").trim()
                if (scheme != "http" && scheme != "https") return NormalizedAddress(false, "", TerminalAddrReason.BAD_FORMAT)
                if (host.isBlank()) return NormalizedAddress(false, "", TerminalAddrReason.BAD_FORMAT)

                // Reject anything that makes base URL ambiguous for message client.
                val hasPath = !(uri.path.isNullOrBlank() || uri.path == "/")
                if (hasPath || !uri.query.isNullOrBlank() || !uri.fragment.isNullOrBlank() || !uri.userInfo.isNullOrBlank()) {
                    return NormalizedAddress(false, "", TerminalAddrReason.AMBIGUOUS)
                }

                val portPart = if (uri.port in 1..65535) ":${uri.port}" else ""
                val base = "${scheme}://${host}${portPart}"
                val isOnion = host.endsWith(".onion", ignoreCase = true)
                NormalizedAddress(isOnion = isOnion, baseUrl = base, terminalReason = null)
            } catch (_: Exception) {
                NormalizedAddress(false, "", TerminalAddrReason.BAD_FORMAT)
            }
        }

        // Non-URL formats must be onion host[:port] only. No path.
        if (s.contains("/") || s.contains("?") || s.contains("#")) {
            return NormalizedAddress(false, "", TerminalAddrReason.AMBIGUOUS)
        }

        val m = HOST_PORT_RE.matchEntire(s) ?: return NormalizedAddress(false, "", TerminalAddrReason.BAD_FORMAT)
        val host = m.groupValues[1].trim()
        val portStr = m.groupValues.getOrNull(2)?.trim().orEmpty()

        if (!ONION_V3_HOST_RE.matches(host)) {
            // Non-onion without scheme is ambiguous and rejected.
            return NormalizedAddress(false, "", TerminalAddrReason.BAD_FORMAT)
        }

        val port = if (portStr.isBlank()) null else portStr.toIntOrNull()
        if (port != null && (port < 1 || port > 65535)) return NormalizedAddress(false, "", TerminalAddrReason.BAD_FORMAT)

        val portPart = if (port != null) ":$port" else ""
        return NormalizedAddress(isOnion = true, baseUrl = "http://${host}${portPart}", terminalReason = null)
    }

    private fun sendSelf(selfFp: String, body: String): SendResult {
        requireValidBody(body)

        val msgId = UUID.randomUUID().toString()
        val createdAt = System.currentTimeMillis()
        val nonce = newNonce()

        val selfOnionHint = identityProvider.invoke()
            ?.onion
            ?.trim()
            ?.takeIf { it.isNotBlank() }

        val (innerBytes, _) = buildInnerV1Bytes(
            msgId = msgId,
            senderFp = selfFp,
            body = body,
            convId = selfFp,
            senderOnionHint = selfOnionHint
        )


        val encRes = cryptoService.encryptAndSignEnvelope(
            senderFingerprint = selfFp,
            recipientFingerprint = selfFp,
            plaintextJsonUtf8 = innerBytes
        )
        if (!encRes.success) {
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = selfFp,
                senderFp = selfFp,
                recipientFp = selfFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            Log.w(TAG, "sendNoteToSelf failed: crypto error msg=${msgId.take(8)} code=${encRes.errorCode}")
            return SendResult.FailedCryptoError(msgId)
        }

        val payloadB64 = encRes.plaintextJson?.optString("payload_pgp", "").orEmpty()

        val payloadB64Clean = payloadB64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        if (payloadB64Clean.isBlank() || payloadB64Clean.length > MAX_PGP_B64_CHARS) {
            Log.w(TAG, "sendX failed: bad payload msg=${msgId.take(8)} len=${payloadB64Clean.length}")
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = selfFp,
                senderFp = selfFp,
                recipientFp = selfFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            return SendResult.FailedCryptoError(msgId)
        }


        // DB stores ciphertext only.
        messageRepo?.storeOutgoingQueued(
            msgId = msgId,
            convId = selfFp,
            senderFp = selfFp,
            recipientFp = selfFp,
            createdAt = createdAt,
            ciphertextBase64 = packStoredCipher(payloadB64Clean)
        )

        val baseUrl = localServerBaseUrlProvider.invoke()
        if (baseUrl.isNullOrBlank()) {
            messageRepo?.markOutgoingQueued(msgId)
            Log.w(TAG, "sendSelf queued: local service not ready msg=${msgId.take(8)}")
            return SendResult.QueuedLocalNotReady(msgId)
        }

        val envelopeStr = buildEnvelopeV1(
            type = ProtocolConfig.TYPE_MESSAGE,
            msgId = msgId,
            senderFp = selfFp,
            recipientFp = selfFp,
            createdAt = createdAt,
            nonce = nonce,
            payloadB64 = payloadB64
        )


        // No sensitive data in logs.
        Log.i(TAG, "sendSelf envelope msg=${msgId.take(8)} created_at=$createdAt nonceLen=${nonce.length} pgpLen=${payloadB64.length}")

        val url = "$baseUrl${com.entrechat.app.config.NetworkConfig.MESSAGE_PATH}"
        val res = localHttpClient.postJson(url, envelopeStr)
        if (!res.ok) {
            messageRepo?.markOutgoingQueued(msgId)
            Log.w(TAG, "sendSelf queued: http fail msg=${msgId.take(8)} http=${res.httpCode}")
            return SendResult.QueuedHttpFail(msgId, res.httpCode)
        }

        messageRepo?.markOutgoingSentOk(msgId)
        Log.i(TAG, "sendSelf ok msg=${msgId.take(8)}")
        return SendResult.Sent(msgId)
    }

    private fun sendRemote(selfFp: String, toFp: String, body: String): SendResult {
        requireValidBody(body)

        val contact = contactDao.getByFingerprint(toFp) ?: throw IllegalStateException("UNKNOWN_CONTACT")
        val addrRaw = contact.onion

        if (contact.trustLevel != ContactEntity.TRUST_VERIFIED) {
            val msgId = UUID.randomUUID().toString()
            Log.w(TAG, "sendRemote blocked: contact not verified to=${fpTag(toFp)} msg=${msgId.take(8)}")
            return SendResult.FailedContactNotVerified(msgId)
        }

        val msgId = UUID.randomUUID().toString()
        val createdAt = System.currentTimeMillis()
        val nonce = newNonce()

        val (innerBytes, _) = buildInnerV1Bytes(
            msgId = msgId,
            senderFp = selfFp,
            body = body,
            convId = selfFp // IMPORTANT: receiver enforces conv_id == sender_fp
        )

        val encRes = cryptoService.encryptAndSignEnvelope(
            senderFingerprint = selfFp,
            recipientFingerprint = toFp,
            plaintextJsonUtf8 = innerBytes
        )
        if (!encRes.success) {
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = toFp,
                senderFp = selfFp,
                recipientFp = toFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            Log.w(TAG, "sendRemote failed: crypto error to=${fpTag(toFp)} msg=${msgId.take(8)} code=${encRes.errorCode}")
            return SendResult.FailedCryptoError(msgId)
        }

        val payloadB64 = encRes.plaintextJson?.optString("payload_pgp", "").orEmpty()

        val payloadB64Clean = payloadB64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        if (payloadB64Clean.isBlank() || payloadB64Clean.length > MAX_PGP_B64_CHARS) {
            Log.w(TAG, "sendX failed: bad payload msg=${msgId.take(8)} len=${payloadB64Clean.length}")
            messageRepo?.storeOutgoingQueued(
                msgId = msgId,
                convId = toFp,
                senderFp = selfFp,
                recipientFp = toFp,
                createdAt = createdAt,
                ciphertextBase64 = "v1|err=crypto"
            )
            messageRepo?.markOutgoingFailed(msgId)
            return SendResult.FailedCryptoError(msgId)
        }

        // Store first, then decide status.
        messageRepo?.storeOutgoingQueued(
            msgId = msgId,
            convId = toFp,
            senderFp = selfFp,
            recipientFp = toFp,
            createdAt = createdAt,
            ciphertextBase64 = packStoredCipher(payloadB64Clean)
        )

        val normalized = normalizeRemoteAddress(addrRaw)
        if (normalized.terminalReason != null) {
            messageRepo?.markOutgoingFailed(msgId)
            val reason = normalized.terminalReason.name
            Log.w(TAG, "sendRemote failed: address $reason to=${fpTag(toFp)} msg=${msgId.take(8)}")
            return when (normalized.terminalReason) {
                TerminalAddrReason.MISSING -> SendResult.FailedMissingAddress(msgId)
                TerminalAddrReason.BAD_FORMAT,
                TerminalAddrReason.AMBIGUOUS -> SendResult.FailedBadAddress(msgId)
            }
        }

        val isOnion = normalized.isOnion
        val baseUrl: String
        val client: RemoteMessageClient

        if (isOnion) {
            val c = synchronized(this) { torClient }
            Log.i(
                TAG,
                "sendRemote sender@${System.identityHashCode(this)} torClient=${
                    c?.let { it::class.java.simpleName + "@" + System.identityHashCode(it) }
                } to=${fpTag(toFp)} msg=${msgId.take(8)}"
            )

            if (c == null) {
                messageRepo?.markOutgoingQueued(msgId)
                Log.w(TAG, "sendRemote queued: tor client null to=${fpTag(toFp)} msg=${msgId.take(8)}")
                return SendResult.QueuedTorNotReady(msgId)
            }
            baseUrl = normalized.baseUrl
            client = c
        } else {
            // Direct HTTP allowed only in debuggable builds.
            if (!isDebuggable()) {
                messageRepo?.markOutgoingFailed(msgId)
                Log.w(TAG, "sendRemote failed: direct http blocked to=${fpTag(toFp)} msg=${msgId.take(8)}")
                return SendResult.FailedBlockedDirectHttp(msgId)
            }
            baseUrl = normalized.baseUrl
            client = remoteMessageClientDirect
        }

        val envelopeStr = buildEnvelopeV1(
            type = ProtocolConfig.TYPE_MESSAGE,
            msgId = msgId,
            senderFp = selfFp,
            recipientFp = toFp,
            createdAt = createdAt,
            nonce = nonce,
            payloadB64 = payloadB64Clean
        )


        val host = hostTag(baseUrl)
        Log.i(TAG, "sendRemote envelope msg=${msgId.take(8)} to=${fpTag(toFp)} host=$host onion=$isOnion httpPayload=${payloadB64Clean.length}")

        val res = client.postMessage(baseUrl, envelopeStr)
        if (!res.ok) {
            messageRepo?.markOutgoingQueued(msgId)
            Log.w(TAG, "sendRemote queued: http fail msg=${msgId.take(8)} http=${res.httpCode} host=$host")
            return SendResult.QueuedHttpFail(msgId, res.httpCode)
        }

        messageRepo?.markOutgoingSentOk(msgId)
        Log.i(TAG, "sendRemote ok msg=${msgId.take(8)} host=$host")
        return SendResult.Sent(msgId)
    }


    /**
     * UI-only helper.
     * Decrypts a PGP payload and verifies signature.
     * Returns plaintext JSON on success, null otherwise.
     *
     * Security:
     * - No logging of plaintext.
     * - No persistence. Caller must keep output in RAM only.
     */
    fun decryptForDisplay(
        senderFp: String,
        recipientFp: String,
        payloadPgpB64: String
    ): JSONObject? {
        val res = try {
            cryptoService.verifyAndDecryptEnvelope(
                senderFingerprint = senderFp,
                recipientFingerprint = recipientFp,
                payloadBase64 = payloadPgpB64
            )
        } catch (_: Throwable) {
            null
        } ?: return null

        if (!res.success) return null
        return res.plaintextJson
    }



    private fun packStoredCipher(pgpB64: String): String {
        val cleaned = pgpB64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        require(cleaned.isNotBlank()) { "packStoredCipher: empty pgp payload" }
        return "v1|pgp=$cleaned"
    }

}
