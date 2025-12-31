/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.common

import android.util.Base64
import com.entrechat.app.config.ProtocolConfig
import com.entrechat.app.db.ContactEntity
import org.json.JSONObject

object JsonContactCodec {

    private const val MAX_PUBLIC_KEY_BYTES = 32 * 1024
    private val V3_HOST_REGEX = Regex("^[a-z2-7]{56}\\.onion$", RegexOption.IGNORE_CASE)
    private val FP_HEX40_RE = Regex("^[0-9A-F]{40}$")

    fun encodeContact(
        fingerprint: String,
        onion: String,
        publicKeyBytes: ByteArray,
        version: Int = ProtocolConfig.VERSION
    ): String {
        val fpCanon = FpFormat.canonical(fingerprint)
        if (!FP_HEX40_RE.matches(fpCanon)) throw IllegalArgumentException("BAD_FINGERPRINT")

        val onionCanon = canonicalizeOnionOrThrow(onion)

        if (publicKeyBytes.isEmpty()) throw IllegalArgumentException("BAD_PUBLIC_KEY_EMPTY")
        if (publicKeyBytes.size > MAX_PUBLIC_KEY_BYTES) throw IllegalArgumentException("BAD_PUBLIC_KEY_TOO_LARGE")

        val pubB64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

        return JSONObject().apply {
            put("v", version)
            put("type", ProtocolConfig.TYPE_CONTACT)
            put("fingerprint", fpCanon)
            put("onion", onionCanon)
            put("pub_b64", pubB64)
        }.toString()
    }

    fun decodeContact(json: String): ContactEntity {
        val obj = JSONObject(json)

        val v = obj.optInt("v", ProtocolConfig.VERSION)
        if (v != ProtocolConfig.VERSION) throw IllegalArgumentException("BAD_VERSION")

        val type = obj.optString("type", ProtocolConfig.TYPE_CONTACT).trim()
        if (type != ProtocolConfig.TYPE_CONTACT && type != "contact") throw IllegalArgumentException("BAD_TYPE")

        val fp = FpFormat.canonical(obj.optString("fingerprint", ""))
        if (!FP_HEX40_RE.matches(fp)) throw IllegalArgumentException("BAD_FINGERPRINT")

        val onionCanon = canonicalizeOnionOrThrow(obj.optString("onion", ""))

        val pubB64 = obj.optString("pub_b64", "").trim()
            .ifBlank { obj.optString("public_key_b64", "").trim() }
        if (pubB64.isBlank()) throw IllegalArgumentException("BAD_PUBLIC_KEY")

        if (pubB64.any { it.isWhitespace() }) throw IllegalArgumentException("BAD_PUBLIC_KEY_B64_WS")

        val pubBytes = try {
            Base64.decode(pubB64, Base64.NO_WRAP)
        } catch (_: Throwable) {
            throw IllegalArgumentException("BAD_PUBLIC_KEY_B64")
        }

        if (pubBytes.isEmpty()) throw IllegalArgumentException("BAD_PUBLIC_KEY_EMPTY")
        if (pubBytes.size > MAX_PUBLIC_KEY_BYTES) throw IllegalArgumentException("BAD_PUBLIC_KEY_TOO_LARGE")

        return ContactEntity(
            fingerprint = fp,
            onion = onionCanon,
            publicKeyBytes = pubBytes,
            trustLevel = ContactEntity.TRUST_UNVERIFIED
        )
    }

    private fun canonicalizeOnionOrThrow(raw: String): String {
        val s = raw.trim()
        if (s.isBlank()) throw IllegalArgumentException("BAD_ONION_EMPTY")

        val lower = s.lowercase()
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            throw IllegalArgumentException("CONTACT_ADDRESS_SCHEME_REJECTED")
        }
        if (lower.indexOf('/') >= 0 || lower.indexOf('?') >= 0 || lower.indexOf('#') >= 0) {
            throw IllegalArgumentException("CONTACT_ADDRESS_HAS_PATH")
        }

        val colonIdx = lower.lastIndexOf(':')
        val host: String
        val port: Int?

        if (colonIdx >= 0) {
            host = lower.substring(0, colonIdx)
            val portStr = lower.substring(colonIdx + 1)
            if (portStr.isEmpty()) throw IllegalArgumentException("CONTACT_ADDRESS_PORT_INVALID")
            if (!portStr.all { it in '0'..'9' }) throw IllegalArgumentException("CONTACT_ADDRESS_PORT_INVALID")
            val p = portStr.toIntOrNull() ?: throw IllegalArgumentException("CONTACT_ADDRESS_PORT_INVALID")
            if (p !in 1..65535) throw IllegalArgumentException("CONTACT_ADDRESS_PORT_RANGE")
            port = p
        } else {
            host = lower
            port = null
        }

        if (!V3_HOST_REGEX.matches(host)) throw IllegalArgumentException("CONTACT_ADDRESS_HOST_INVALID")
        return if (port == null) host else "$host:$port"
    }
}
