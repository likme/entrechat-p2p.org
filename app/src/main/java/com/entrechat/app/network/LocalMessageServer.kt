/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import com.entrechat.app.EntrechatServiceManager
import com.entrechat.app.config.LimitsConfig
import com.entrechat.app.config.NetworkConfig
import com.entrechat.app.config.ProtocolConfig
import com.entrechat.app.db.ContactDao
import com.entrechat.app.db.ContactEntity
import com.entrechat.app.db.IdentityEntity
import com.entrechat.app.db.InviteDao
import com.entrechat.app.db.MessageDao
import com.entrechat.app.db.UpsertResult
import com.entrechat.app.debug.RuntimeFile
import fi.iki.elonen.NanoHTTPD
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class LocalMessageServer(
    private val messageHandler: IncomingMessageHandler,
    private val identityProvider: () -> IdentityEntity?,
    private val contactDaoProvider: () -> ContactDao,
    private val messageDaoProvider: () -> MessageDao,
    private val inviteDaoProvider: () -> InviteDao,
    private val appContext: Context,
    host: String = NetworkConfig.LOCAL_HOST,
    port: Int = 0,
) : NanoHTTPD(host, port) {

    @Volatile private var boundPort: Int = -1

    fun startAndGetBoundPort(timeoutMs: Int, daemon: Boolean): Int {
        start(timeoutMs, daemon)
        boundPort = listeningPort
        if (boundPort <= 0) throw IllegalStateException("LocalMessageServer failed to bind (listeningPort=$boundPort)")
        Log.i("LocalMessageServer", "BOUND http://$hostname:$boundPort")

        RuntimeFile.write(
            appCtx = appContext,
            state = "HTTP_BOUND",
            onion = null,
            localPort = boundPort,
            socksHost = null,
            socksPort = null
        )

        return boundPort
    }

    fun getBoundPortOrNull(): Int? = boundPort.takeIf { it > 0 }

    override fun serve(session: IHTTPSession): Response {
        return try {
            val method = session.method
            val uri = session.uri

            if (isDebuggable()) {
                val len = session.headers["content-length"] ?: "-"
                val ct = session.headers["content-type"] ?: "-"
                Log.d("LocalMessageServer", "IN $method $uri len=$len ct=$ct")
            }

            if (method == Method.GET && uri == NetworkConfig.HEALTH_PATH) {
                val st = EntrechatServiceManager.getState()
                val ready = st is EntrechatServiceManager.AppState.TOR_READY

                val body = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION,
                        "ok" to ready,
                        "state" to when (st) {
                            is EntrechatServiceManager.AppState.INIT -> "INIT"
                            is EntrechatServiceManager.AppState.TOR_STARTING -> "TOR_STARTING"
                            is EntrechatServiceManager.AppState.TOR_READY -> "TOR_READY"
                            is EntrechatServiceManager.AppState.ERROR -> "ERROR"
                        },
                        "detail" to (st as? EntrechatServiceManager.AppState.TOR_STARTING)?.detail,
                        "local_port" to (getBoundPortOrNull() ?: -1)
                    )
                ).toString()

                val status = if (ready) Response.Status.OK else Response.Status.SERVICE_UNAVAILABLE
                return newFixedLengthResponse(status, "application/json", body)
            }

            if (method == Method.GET && uri == "/v1/debug/state") {
                if (!isDebuggable()) return notFound()

                val st = EntrechatServiceManager.getState()
                val body = when (st) {
                    is EntrechatServiceManager.AppState.INIT ->
                        JSONObject(mapOf("state" to "INIT"))

                    is EntrechatServiceManager.AppState.TOR_STARTING ->
                        JSONObject(mapOf("state" to "TOR_STARTING", "detail" to st.detail))

                    is EntrechatServiceManager.AppState.TOR_READY ->
                        JSONObject(
                            mapOf(
                                "state" to "TOR_READY",
                                "onion" to st.runtime.onion,
                                "localPort" to st.runtime.localPort,
                                "socksHost" to st.runtime.socksHost,
                                "socksPort" to st.runtime.socksPort
                            )
                        )

                    is EntrechatServiceManager.AppState.ERROR ->
                        JSONObject(mapOf("state" to "ERROR", "code" to st.code, "detail" to st.detail))
                }.put("v", ProtocolConfig.VERSION).put("ok", true).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", body)
            }

            if (method == Method.GET && uri == NetworkConfig.IDENTITY_PATH) {
                if (!isDebuggable()) return notFound()
                val identity = identityProvider.invoke()
                val body = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION,
                        "ok" to (identity != null),
                        "fingerprint" to (identity?.fingerprint ?: ""),
                        "onion_present" to (!identity?.onion.isNullOrBlank()),
                        "pub_len" to (identity?.publicKeyBytes?.size ?: 0),
                        "local_port" to (getBoundPortOrNull() ?: -1),
                    )
                ).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", body)
            }

            if (method == Method.GET && uri == NetworkConfig.CONTACT_EXPORT_PATH) {
                if (!isDebuggable()) return notFound()
                val identity = identityProvider.invoke()
                if (identity == null) {
                    val body = JSONObject(
                        mapOf(
                            "v" to ProtocolConfig.VERSION,
                            "ok" to false,
                            "code" to "NO_IDENTITY"
                        )
                    ).toString()
                    return newFixedLengthResponse(Response.Status.OK, "application/json", body)
                }

                val onion = identity.onion?.trim().orEmpty()
                if (onion.isBlank() || !isValidOnionV3(onion.lowercase())) {
                    val body = JSONObject(
                        mapOf(
                            "v" to ProtocolConfig.VERSION,
                            "ok" to false,
                            "code" to "NO_ONION"
                        )
                    ).toString()
                    return newFixedLengthResponse(Response.Status.OK, "application/json", body)
                }

                val pubB64 = android.util.Base64.encodeToString(
                    identity.publicKeyBytes,
                    android.util.Base64.NO_WRAP
                )

                val body = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION,
                        "type" to ProtocolConfig.TYPE_CONTACT,
                        "fingerprint" to identity.fingerprint.trim().uppercase(),
                        "onion" to onion,
                        "pub_b64" to pubB64
                    )
                ).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", body)
            }

            if (method == Method.GET && uri == NetworkConfig.MESSAGES_PATH) {
                if (!isDebuggable()) return notFound()

                val params = session.parameters
                val convId = params["conv_id"]?.firstOrNull()?.trim()
                val limitRaw = params["limit"]?.firstOrNull()?.trim()
                val limit = (limitRaw?.toIntOrNull() ?: 50).coerceIn(1, 500)

                val messageDao = messageDaoProvider.invoke()
                val messages = runBlocking(Dispatchers.IO) {
                    messageDao.list(convId?.takeIf { it.isNotEmpty() }, limit)
                }

                val arr = JSONArray()
                for (m in messages) {
                    arr.put(
                        JSONObject(
                            mapOf(
                                "msgId" to m.msgId,
                                "convId" to m.convId,
                                "direction" to m.direction,
                                "senderFp" to m.senderFp,
                                "recipientFp" to m.recipientFp,
                                "createdAt" to m.createdAt,
                                "status" to m.status,
                                "serverReceivedAt" to m.serverReceivedAt,
                                "ciphertextBase64" to m.ciphertextBase64
                            )
                        )
                    )
                }

                val out = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION,
                        "ok" to true,
                        "messages" to arr
                    )
                ).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", out)
            }

            if (method == Method.GET && uri == "/v1/debug/contacts") {
                if (!isDebuggable()) return notFound()

                val contactDao = contactDaoProvider.invoke()
                val contacts = runBlocking(Dispatchers.IO) {
                    contactDao.list(500)
                }

                val arr = JSONArray()
                for (c in contacts) {
                    arr.put(
                        JSONObject(
                            mapOf(
                                "fingerprint" to c.fingerprint,
                                "onion" to c.onion,
                                "pub_len" to c.publicKeyBytes.size,
                                "createdAt" to c.createdAt
                            )
                        )
                    )
                }

                val out = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION,
                        "ok" to true,
                        "count" to contacts.size,
                        "contacts" to arr
                    )
                ).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", out)
            }

            if (method == Method.GET && uri.startsWith(ProtocolConfig.INVITE_PATH_PREFIX)) {
                val token = uri.removePrefix(ProtocolConfig.INVITE_PATH_PREFIX).trim()
                if (!isValidInviteToken(token)) return notFound()

                val identity = identityProvider.invoke()
                    ?: return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "NO_IDENTITY", null)

                val onion = identity.onion.trim().lowercase()
                if (onion.isBlank() || !isValidOnionV3(onion)) {
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "NO_ONION", null)
                }

                val inviteDao = inviteDaoProvider.invoke()
                val nowMs = System.currentTimeMillis()

                val invite = runBlocking(Dispatchers.IO) { inviteDao.findByToken(token) } ?: return notFound()

                if (invite.isUsed) return error(HttpStatuses.CONFLICT_409, "INVITE_USED", null)
                if (invite.isExpired(nowMs)) return error(HttpStatuses.GONE_410, "INVITE_EXPIRED", null)

                val updated = runBlocking(Dispatchers.IO) {
                    inviteDao.markUsedIfValid(
                        token = token,
                        usedAtMs = nowMs,
                        nowMs = nowMs,
                        usedByHint = null
                    )
                }
                if (updated != 1) return error(HttpStatuses.CONFLICT_409, "INVITE_USED", null)

                val pubB64 = android.util.Base64.encodeToString(identity.publicKeyBytes, android.util.Base64.NO_WRAP)

                val body = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION_INVITE_V2,
                        "ok" to true,
                        "type" to "invite_accept",
                        "protocol" to "ec2",
                        "fingerprint" to identity.fingerprint.trim().uppercase(),
                        "primary_onion" to onion,
                        "pub_b64" to pubB64,
                        "pub_fmt" to "pgp",
                        "ts" to (nowMs / 1000)
                    )
                ).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", body)
            }


            if (method != Method.POST) return badRequest("BAD_METHOD")

            val isMessage = (uri == NetworkConfig.MESSAGE_PATH) || (uri == ProtocolConfig.API_BASE_PATH + "/message")
            val isContactImport = uri == NetworkConfig.CONTACT_IMPORT_PATH
            if (!isMessage && !isContactImport) return notFound()

            val bodyStr = try {
                readBody(session)
            } catch (_: PayloadTooLargeException) {
                return payloadTooLarge()
            } catch (_: Exception) {
                return badRequest("INVALID_BODY")
            }

            if (bodyStr.isBlank()) return badRequest("INVALID_BODY")

            val json = try {
                JSONObject(bodyStr)
            } catch (_: Exception) {
                return badRequest("INVALID_JSON")
            }

            if (json.optInt("v") != ProtocolConfig.VERSION) return badRequest("UNSUPPORTED_VERSION")
            val type = json.optString("type", "").trim()

            if (isContactImport) {
                if (type != ProtocolConfig.TYPE_CONTACT) return badRequest("INVALID_TYPE")

                val fp = json.optString("fingerprint", "").trim().uppercase()
                val selfFp = identityProvider.invoke()?.fingerprint?.trim()?.uppercase()
                Log.i("LocalMessageServer", "contact_import fp=$fp selfFp_present=${!selfFp.isNullOrBlank()}")
                if (!selfFp.isNullOrBlank() && fp == selfFp) {
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "SELF_CONTACT_NOT_ALLOWED", null)
                }

                val onionRaw = json.optString("onion", "").trim()
                val pubB64 = json.optString("pub_b64", "").trim()

                if (!isValidFingerprint(fp)) {
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "INVALID_FINGERPRINT", null)
                }

                val onion = onionRaw.lowercase()
                if (onion.isBlank()) {
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "MISSING_ONION", null)
                }
                if (!isValidOnionV3(onion)) {
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "INVALID_ONION", null)
                }

                val pubBytes = try {
                    android.util.Base64.decode(pubB64, android.util.Base64.NO_WRAP)
                } catch (_: Exception) {
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "INVALID_PUB_B64", null)
                }

                try {
                    com.entrechat.app.crypto.PgpKeyLoader.loadPublicKey(pubBytes)
                } catch (_: Exception) {
                    pubBytes.fill(0)
                    return error(HttpStatuses.UNPROCESSABLE_ENTITY_422, "INVALID_PUBKEY", null)
                }

                val contactDao = contactDaoProvider.invoke()

                val upsertResult: UpsertResult = runBlocking(Dispatchers.IO) {
                    contactDao.upsertMergeSafe(
                        ContactEntity(
                            fingerprint = fp,
                            onion = onion,
                            publicKeyBytes = pubBytes
                        )
                    )
                }

                val pending = upsertResult is UpsertResult.PendingApproval

                val out = JSONObject(
                    mapOf(
                        "v" to ProtocolConfig.VERSION,
                        "ok" to true,
                        "pending_approval" to pending
                    )
                ).toString()

                return newFixedLengthResponse(Response.Status.OK, "application/json", out)
            }

            if (type != ProtocolConfig.TYPE_MESSAGE) return badRequest("INVALID_TYPE")

            val result = messageHandler.handleIncoming(json)
            return when (result) {
                is IncomingMessageResult.Ok -> ok(result.msgId)
                is IncomingMessageResult.Rejected -> error(result.httpCode, result.errorCode, result.msgId)
            }

        } catch (t: Throwable) {
            Log.e("LocalMessageServer", "Unhandled error in serve()", t)
            val body = JSONObject(
                mapOf(
                    "v" to ProtocolConfig.VERSION,
                    "ok" to false,
                    "code" to "INTERNAL_ERROR"
                )
            ).toString()
            newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "application/json", body)
        }
    }

    private fun isDebuggable(): Boolean {
        val flags = appContext.applicationInfo.flags
        return (flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    private fun isValidFingerprint(fp: String): Boolean {
        if (fp.length != 40) return false
        for (c in fp) {
            val ok = (c in '0'..'9') || (c in 'A'..'F')
            if (!ok) return false
        }
        return true
    }

    private fun isValidOnionV3(onion: String): Boolean {
        if (!onion.endsWith(".onion")) return false
        val host = onion.removeSuffix(".onion")
        if (host.length != 56) return false
        for (c in host) {
            val ok = (c in 'a'..'z') || (c in '2'..'7')
            if (!ok) return false
        }
        return true
    }

    private fun isValidInviteToken(token: String): Boolean {
        if (token.length < 22 || token.length > 128) return false
        for (c in token) {
            val ok =
                (c in 'A'..'Z') ||
                    (c in 'a'..'z') ||
                    (c in '0'..'9') ||
                    c == '-' ||
                    c == '_'
            if (!ok) return false
        }
        return true
    }

    private class PayloadTooLargeException : RuntimeException()

    private fun readBody(session: IHTTPSession): String {
        val len = session.headers["content-length"]?.toIntOrNull() ?: 0
        return if (len > 0) {
            readBodyCompat(session)
        } else {
            val files = HashMap<String, String>()
            session.parseBody(files)
            val postData = files["postData"].orEmpty()
            if (postData.isBlank()) return ""

            val f = File(postData)
            val bytes = if (f.exists() && f.isFile) f.readBytes() else postData.toByteArray(Charsets.UTF_8)
            if (bytes.size > LimitsConfig.MAX_HTTP_PAYLOAD_BYTES) {
                bytes.fill(0)
                throw PayloadTooLargeException()
            }
            val s = String(bytes, Charsets.UTF_8)
            bytes.fill(0)
            s
        }
    }

    private fun readBodyCompat(session: IHTTPSession): String {
        val files = HashMap<String, String>()
        session.parseBody(files)

        val body = files["postData"].orEmpty()

        if (body.toByteArray(Charsets.UTF_8).size > LimitsConfig.MAX_HTTP_PAYLOAD_BYTES) {
            throw PayloadTooLargeException()
        }

        return body
    }

    private fun ok(msgId: String): Response =
        newFixedLengthResponse(
            Response.Status.OK,
            "application/json",
            JSONObject(
                mapOf(
                    "v" to ProtocolConfig.VERSION,
                    "ok" to true,
                    "msg_id" to msgId
                )
            ).toString()
        )

    private fun error(
        status: Response.IStatus,
        code: String,
        msgId: String?
    ): Response {
        val resp = newFixedLengthResponse(
            status,
            "application/json",
            JSONObject(
                mapOf(
                    "v" to ProtocolConfig.VERSION,
                    "ok" to false,
                    "code" to code,
                    "msg_id" to msgId
                )
            ).toString()
        )
        resp.addHeader("Connection", "close")
        return resp
    }

    private fun badRequest(code: String) =
        error(Response.Status.BAD_REQUEST, code, null)

    private fun notFound(): Response {
        val body = JSONObject(
            mapOf(
                "v" to ProtocolConfig.VERSION,
                "ok" to false,
                "code" to "NOT_FOUND"
            )
        ).toString()
        return newFixedLengthResponse(Response.Status.NOT_FOUND, "application/json", body)
    }

    private fun payloadTooLarge() =
        error(HttpStatuses.REQUEST_ENTITY_TOO_LARGE_413, "PAYLOAD_TOO_LARGE", null)
}
