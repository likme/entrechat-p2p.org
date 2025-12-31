/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import com.entrechat.app.config.HeadersConfig
import com.entrechat.app.config.NetworkConfig
import com.entrechat.app.config.TorConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * HTTP client forced through Tor SOCKS proxy.
 * Entrechat v1.
 */
object TorHttpClient {

    private val jsonMediaType = HeadersConfig.CONTENT_TYPE_JSON.toMediaType()

    private val torProxy: Proxy by lazy {
        Proxy(
            Proxy.Type.SOCKS,
            InetSocketAddress(TorConfig.SOCKS_HOST, TorConfig.SOCKS_PORT)
        )
    }

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .proxy(torProxy)
            .connectTimeout(NetworkConfig.CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(NetworkConfig.READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(NetworkConfig.WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }

    /**
     * POST JSON to a remote onion service.
     *
     * @param onion Onion address (xxxxxxxx.onion)
     * @param path API path (ex: /v1/message)
     * @param jsonBody UTF-8 JSON string
     */
    fun postJson(
        onion: String,
        path: String,
        jsonBody: String
    ): HttpResult {

        val url = buildUrl(onion, path)

        val body = jsonBody.toRequestBody(jsonMediaType)

        val request = Request.Builder()
            .url(url)
            .post(body)
            .header(HeadersConfig.HEADER_CONTENT_TYPE, HeadersConfig.CONTENT_TYPE_JSON)
            .header(HeadersConfig.HEADER_USER_AGENT, HeadersConfig.USER_AGENT)
            .build()

        return try {
            httpClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                HttpResult(
                    success = response.isSuccessful,
                    code = response.code,
                    body = responseBody
                )
            }
        } catch (e: Exception) {
            HttpResult(
                success = false,
                code = null,
                body = null,
                error = e
            )
        }
    }

    private fun buildUrl(onion: String, path: String): String {
        // Onion services use http, not https
        return "http://$onion:${NetworkConfig.ONION_VIRTUAL_PORT}$path"
    }
}
