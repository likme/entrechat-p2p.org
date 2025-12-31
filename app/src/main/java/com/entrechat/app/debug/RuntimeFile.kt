/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.debug

import android.content.Context
import org.json.JSONObject
import java.io.File

object RuntimeFile {

    private const val FILE_NAME = "runtime.json"

    private fun cleanStr(s: String?): String? =
        s?.trim()
            ?.takeIf { it.isNotEmpty() && !it.equals("null", ignoreCase = true) }

    private fun cleanPort(p: Int?): Int? = p?.takeIf { it in 1..65535 }

    private fun readPrevJson(file: File): JSONObject? {
        if (!file.exists()) return null
        val text = runCatching { file.readText() }.getOrNull() ?: return null
        return runCatching { JSONObject(text) }.getOrNull()
    }

    private fun optNullableString(o: JSONObject?, key: String): String? {
        if (o == null) return null
        if (!o.has(key) || o.isNull(key)) return null
        return cleanStr(o.optString(key))
    }

    private fun optNullableInt(o: JSONObject?, key: String): Int? {
        if (o == null) return null
        if (!o.has(key) || o.isNull(key)) return null
        return cleanPort(o.optInt(key))
    }

    fun write(
        appCtx: Context,
        state: String,
        onion: String?,
        localPort: Int?,
        socksHost: String?,
        socksPort: Int?,
        errorCode: String? = null,
        errorDetail: String? = null
    ) {
        runCatching {
            val f = File(appCtx.filesDir, FILE_NAME)
            val prev = readPrevJson(f)

            val prevOnion = optNullableString(prev, "onion")
            val prevSocksHost = optNullableString(prev, "socksHost")
            val prevLocalPort = optNullableInt(prev, "localPort")
            val prevSocksPort = optNullableInt(prev, "socksPort")
            val prevErrorCode = optNullableString(prev, "errorCode")
            val prevErrorDetail = optNullableString(prev, "errorDetail")

            val mergedOnion = cleanStr(onion) ?: prevOnion
            val mergedLocalPort = cleanPort(localPort) ?: prevLocalPort
            val mergedSocksHost = cleanStr(socksHost) ?: prevSocksHost
            val mergedSocksPort = cleanPort(socksPort) ?: prevSocksPort
            val mergedErrorCode = cleanStr(errorCode) ?: prevErrorCode
            val mergedErrorDetail = cleanStr(errorDetail) ?: prevErrorDetail

            val merged = JSONObject().apply {
                put("v", 1)
                put("state", state)
                put("onion", mergedOnion ?: JSONObject.NULL)
                put("localPort", mergedLocalPort ?: JSONObject.NULL)
                put("socksHost", mergedSocksHost ?: JSONObject.NULL)
                put("socksPort", mergedSocksPort ?: JSONObject.NULL)
                put("errorCode", mergedErrorCode ?: JSONObject.NULL)
                put("errorDetail", mergedErrorDetail ?: JSONObject.NULL)
                put("ts", System.currentTimeMillis())
            }

            f.writeText(merged.toString())
        }
    }

    fun delete(appCtx: Context) {
        runCatching {
            val f = File(appCtx.filesDir, FILE_NAME)
            if (f.exists()) f.delete()
        }
    }
}
