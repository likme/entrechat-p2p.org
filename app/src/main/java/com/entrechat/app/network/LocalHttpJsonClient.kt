/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class LocalHttpJsonClient {

    data class HttpResult(val httpCode: Int, val body: String) {
        val ok: Boolean get() = httpCode in 200..299
    }

    fun postJson(url: String, jsonBody: String): HttpResult {
        val conn = (URL(url).openConnection() as HttpURLConnection)

        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Connection", "close")

        val bytes = jsonBody.toByteArray(Charsets.UTF_8)
        conn.setFixedLengthStreamingMode(bytes.size)

        conn.outputStream.use { it.write(bytes) }

        val code = conn.responseCode
        val stream = if (code >= 400) conn.errorStream else conn.inputStream
        val body = stream?.let { s ->
            BufferedReader(InputStreamReader(s, Charsets.UTF_8)).use { it.readText() }
        } ?: ""

        conn.disconnect()
        Log.i("LocalHttpJsonClient", "POST $url -> $code (${body.length} bytes)")
        return HttpResult(code, body)
    }
}
