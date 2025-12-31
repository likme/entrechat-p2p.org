/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.chat

import android.util.Base64
import com.entrechat.app.db.MessageEntity
import org.json.JSONObject

/**
 * UI-friendly representation of a chat message row.
 *
 * Security:
 * - DB stores ciphertext only ("pgp="). No plaintext ("pt=") is expected.
 * - This row never decrypts. It only shows a neutral placeholder for encrypted content.
 * - No sensitive data is logged.
 */
data class ChatRow(
    val msgId: String,
    val direction: String, // "IN" | "OUT"
    val createdAt: Long,
    val status: String,
    val bodyPreview: String
) {
    companion object {
        private const val PREVIEW_MAX_CHARS = 400
        private const val FALLBACK_HEAD = 24
        private const val MAX_DECODE_BYTES = 64 * 1024

        private const val ENCRYPTED_LABEL = "(encrypted)"
        private const val EMPTY_LABEL = "(empty)"

        fun fromEntity(e: MessageEntity): ChatRow {
            return ChatRow(
                msgId = e.msgId,
                direction = e.direction,
                createdAt = e.createdAt,
                status = e.status,
                bodyPreview = buildPreview(e.ciphertextBase64)
            )
        }

        private fun buildPreview(cipherField: String?): String {
            val raw = cipherField?.trim().orEmpty()
            if (raw.isBlank()) return EMPTY_LABEL

            // Container v1: v1|pgp=...
            if (raw.startsWith("v1|")) {
                val map = parseContainerV1(raw)
                val pgpB64 = map["pgp"].orEmpty()
                return encryptedFallback(pgpB64)
            }

            // Legacy: keep best-effort for old DB rows that still stored JSON or base64(JSON)
            tryParseBodyFromJsonString(raw)?.let { return it.toPreview() }
            safeBase64DecodeToString(raw)?.let { decoded ->
                tryParseBodyFromJsonString(decoded)?.let { return it.toPreview() }
            }

            return encryptedFallback(raw)
        }

        private fun encryptedFallback(s: String): String {
            val head = s.trim().take(FALLBACK_HEAD)
            return if (head.isBlank()) ENCRYPTED_LABEL else "$ENCRYPTED_LABEL $head…"
        }

        private fun String.toPreview(): String {
            val cleaned = this
                .replace("\u0000", "")
                .replace(Regex("\\s+"), " ")
                .trim()

            if (cleaned.isBlank()) return EMPTY_LABEL
            return if (cleaned.length <= PREVIEW_MAX_CHARS) cleaned
            else cleaned.substring(0, PREVIEW_MAX_CHARS) + "…"
        }

        private fun tryParseBodyFromJsonString(s: String?): String? {
            val str = s?.trim().orEmpty()
            if (str.isBlank()) return null
            if (!str.startsWith("{") || !str.endsWith("}")) return null

            return try {
                val obj = JSONObject(str)
                val body = obj.optString("body", "").trim()
                body.takeIf { it.isNotBlank() }
            } catch (_: Throwable) {
                null
            }
        }

        private fun safeBase64DecodeToString(b64: String?): String? {
            val s = b64?.trim().orEmpty()
            if (s.isBlank()) return null
            if (s.length > (MAX_DECODE_BYTES * 2)) return null

            val bytes = try {
                Base64.decode(s, Base64.NO_WRAP)
            } catch (_: Throwable) {
                null
            } ?: return null

            if (bytes.size > MAX_DECODE_BYTES) return null

            return try {
                String(bytes, Charsets.UTF_8)
            } catch (_: Throwable) {
                null
            }
        }

        private fun parseContainerV1(raw: String): Map<String, String> {
            val out = LinkedHashMap<String, String>(4)
            val parts = raw.split('|')
            for (p in parts) {
                val idx = p.indexOf('=')
                if (idx <= 0) continue
                val k = p.substring(0, idx).trim()
                if (k.isEmpty()) continue
                val v = p.substring(idx + 1)
                out[k] = v
            }
            return out
        }
    }
}
