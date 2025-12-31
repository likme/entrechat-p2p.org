/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import android.util.Log
import com.entrechat.app.config.NetworkConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class RemoteMessageClient(
    private val http: OkHttpClient
) {

    companion object {
        private const val TAG = "RemoteMessageClient"
        private val JSON = "application/json".toMediaType()

        fun buildDefaultClient(): OkHttpClient {
            return OkHttpClient.Builder()
                .connectTimeout(NetworkConfig.CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .readTimeout(NetworkConfig.READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .writeTimeout(NetworkConfig.WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(false)
                .build()
        }
    }

    data class Result(
        val ok: Boolean,
        val httpCode: Int,
        val body: String?
    )

    fun postMessage(baseUrl: String, envelopeJson: String): Result {
        val url = baseUrl.trimEnd('/') + NetworkConfig.MESSAGE_PATH

        val req = Request.Builder()
            .url(url)
            .post(envelopeJson.toRequestBody(JSON))
            .build()

        return execute(req)
    }

    fun get(pathUrl: String): Result {
        val req = Request.Builder()
            .url(pathUrl)
            .get()
            .build()

        return execute(req)
    }

    fun getInvite(ephemeralOnion: String, token: String): Result {
        val host = ephemeralOnion.trim().lowercase()
        require(host.endsWith(".onion")) { "BAD_ONION" }
        val t = token.trim()
        val url = "http://$host${com.entrechat.app.config.ProtocolConfig.INVITE_PATH_PREFIX}$t"
        return get(url)
    }

    private fun sanitizeUrl(url: String): String {
        val u = url.trim()
        val i = u.indexOf(".onion")
        if (i < 0) return u
        val start = (u.lastIndexOf("://", startIndex = i).takeIf { it >= 0 }?.plus(3)) ?: 0
        val end = i + ".onion".length
        val host = u.substring(start, end)
        val masked = host.take(6) + "…" + host.takeLast(6)
        return u.replace(host, masked)
    }


    private fun execute(req: Request): Result {
        val url = sanitizeUrl(req.url.toString())
        return try {
            http.newCall(req).execute().use { resp ->
                val body = resp.body?.string()
                val code = resp.code

                if (resp.isSuccessful) {
                    Log.i(TAG, "${req.method} $url -> $code")
                } else {
                    val short = body?.take(300)
                    Log.w(TAG, "${req.method} $url -> $code body=$short")
                }

                Result(ok = resp.isSuccessful, httpCode = code, body = body)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "${req.method} $url failed: ${t.message}", t)
            Result(ok = false, httpCode = 0, body = null)
        }
    }
}
