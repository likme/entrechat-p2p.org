/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.common

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.zip.Inflater

object Ec1QrCodec {

    // New compact single-QR:
    // ec1|<b64url(binary)>
    //
    // Legacy single-part:
    // EC1|1/1|<b64(zlib-deflate(jsonUtf8))>
    // ec1|1/1|<b64(zlib-deflate(jsonUtf8))>
    private const val PREFIX_COMPACT = "ec1|"

    private const val MAGIC_0: Byte = 'E'.code.toByte()
    private const val MAGIC_1: Byte = 'C'.code.toByte()
    private const val MAGIC_2: Byte = '1'.code.toByte()
    private const val VERSION: Byte = 1

    // Limits to prevent abuse
    private const val MAX_ONION_CHARS = 128
    private const val MAX_COMPRESSED_BYTES = 256_000
    private const val MAX_JSON_BYTES = 256_000

    fun isEc1(text: String): Boolean {
        val t = text.trim()
        return t.startsWith("EC1|") || t.startsWith("ec1|")
    }

    /**
     * Encodes a JSON contact (as produced by JsonContactCodec) into a single compact QR payload.
     *
     * This avoids multi-part QR pages by transporting a binary payload with a short checksum.
     */
    fun encodeFromContactJson(jsonUtf8: String): String {
        val jsonBytes = jsonUtf8.toByteArray(Charsets.UTF_8)
        require(jsonBytes.isNotEmpty()) { "EC1_EMPTY_JSON" }
        require(jsonBytes.size <= MAX_JSON_BYTES) { "EC1_JSON_TOO_LARGE" }

        val obj = org.json.JSONObject(jsonUtf8)
        val fp = FpFormat.canonical(obj.optString("fingerprint", ""))
        if (fp.isBlank()) throw IllegalArgumentException("EC1_BAD_FINGERPRINT")

        val onion = obj.optString("onion", "").trim()
        if (onion.isBlank() || onion.length > MAX_ONION_CHARS) throw IllegalArgumentException("EC1_BAD_ONION")

        val pubB64 = obj.optString("pub_b64", "").trim().ifBlank { obj.optString("public_key_b64", "").trim() }
        if (pubB64.isBlank()) throw IllegalArgumentException("EC1_BAD_PUBLIC_KEY")

        // Decode pubkey bytes (raw), then deflate for size.
        val pubBytes = try {
            Base64.decode(pubB64, Base64.NO_WRAP)
        } catch (_: Throwable) {
            throw IllegalArgumentException("EC1_BAD_PUBLIC_KEY_B64")
        }
        if (pubBytes.isEmpty()) throw IllegalArgumentException("EC1_BAD_PUBLIC_KEY_EMPTY")

        val compressedPub = zlibDeflate(pubBytes)
        if (compressedPub.size > MAX_COMPRESSED_BYTES) throw IllegalArgumentException("EC1_PUBKEY_TOO_LARGE")

        // Compact binary payload:
        // [EC1][ver][fpLen u16][fpHex ASCII][onionLen u16][onion UTF8][compLen u32][compBytes][ck4]
        val payloadNoCk = ByteArrayOutputStream().use { baos ->
            DataOutputStream(baos).use { out ->
                out.writeByte(MAGIC_0.toInt())
                out.writeByte(MAGIC_1.toInt())
                out.writeByte(MAGIC_2.toInt())
                out.writeByte(VERSION.toInt())

                val fpAscii = fp.toByteArray(Charsets.US_ASCII)
                out.writeShort(fpAscii.size)
                out.write(fpAscii)

                val onionBytes = onion.lowercase().toByteArray(Charsets.UTF_8)
                out.writeShort(onionBytes.size)
                out.write(onionBytes)

                out.writeInt(compressedPub.size)
                out.write(compressedPub)
            }
            baos.toByteArray()
        }

        val ck4 = sha256(payloadNoCk).copyOfRange(0, 4)
        val full = ByteArrayOutputStream().use { baos ->
            baos.write(payloadNoCk)
            baos.write(ck4)
            baos.toByteArray()
        }

        val b64url = Base64.encodeToString(full, Base64.NO_WRAP or Base64.URL_SAFE)
        return PREFIX_COMPACT + b64url
    }

    /**
     * Decodes either:
     * - Compact single-QR ec1|<b64url(binary)>   (recommended)
     * - Legacy single-part EC1|1/1|<b64(zlib(jsonUtf8))>
     *
     * Returns JSON UTF-8 string (contact JSON).
     */
    fun decodeToJsonUtf8Any(text: String): String {
        val t = text.trim()
        if (!isEc1(t)) throw IllegalArgumentException("EC1_NOT_EC1")

        // If format is exactly "ec1|<payload>", treat as compact (Option A).
        val parts2 = t.split("|", limit = 2)
        if (parts2.size == 2 && (parts2[0] == "ec1" || parts2[0] == "EC1")) {
            // Ambiguous with legacy which has 3 parts. If only 2 parts, it's compact.
            if (!t.contains("|1/1|")) {
                val b64 = parts2[1].trim()
                val json = decodeCompactToJson(b64) ?: throw IllegalArgumentException("EC1_BAD_COMPACT")
                return json
            }
        }

        // Otherwise treat as legacy 3-part: EC1|1/1|payload
        return decodeLegacyToJsonUtf8(t)
    }

    /**
     * Legacy: EC1|1/1|<b64(zlib-deflate(jsonUtf8))>
     */
    fun decodeLegacyToJsonUtf8(text: String): String {
        val t = text.trim()

        val parts = t.split("|", limit = 3)
        if (parts.size != 3) throw IllegalArgumentException("EC1_BAD_FORMAT")

        val magic = parts[0]
        if (magic != "EC1" && magic != "ec1") throw IllegalArgumentException("EC1_BAD_MAGIC")

        val idxTot = parts[1]
        val payloadB64 = parts[2]
        if (payloadB64.isBlank()) throw IllegalArgumentException("EC1_BAD_PAYLOAD")

        val idxParts = idxTot.split("/", limit = 2)
        if (idxParts.size != 2) throw IllegalArgumentException("EC1_BAD_INDEX")

        val i = idxParts[0].toIntOrNull() ?: -1
        val n = idxParts[1].toIntOrNull() ?: -1
        if (!(i == 1 && n == 1)) throw IllegalArgumentException("EC1_EXPECT_1_1")

        val deflated = try {
            Base64.decode(payloadB64, Base64.DEFAULT)
        } catch (_: Throwable) {
            throw IllegalArgumentException("EC1_BAD_B64")
        }

        val jsonBytes = inflateZlib(deflated)
        if (jsonBytes.size > MAX_JSON_BYTES) throw IllegalArgumentException("EC1_JSON_TOO_LARGE")

        val out = try {
            jsonBytes.toString(Charsets.UTF_8)
        } catch (_: Throwable) {
            throw IllegalArgumentException("EC1_BAD_UTF8")
        }

        if (out.isBlank()) throw IllegalArgumentException("EC1_EMPTY_JSON")
        return out
    }

    private fun decodeCompactToJson(b64url: String): String? {
        val all = try {
            Base64.decode(b64url, Base64.NO_WRAP or Base64.URL_SAFE)
        } catch (_: Throwable) {
            return null
        }
        if (all.size < 3 + 1 + 2 + 2 + 4 + 4) return null

        val payloadNoCk = all.copyOfRange(0, all.size - 4)
        val ck = all.copyOfRange(all.size - 4, all.size)
        val exp = sha256(payloadNoCk).copyOfRange(0, 4)
        if (!ck.contentEquals(exp)) return null

        return try {
            DataInputStream(ByteArrayInputStream(payloadNoCk)).use { input ->
                val m0 = input.readByte()
                val m1 = input.readByte()
                val m2 = input.readByte()
                val ver = input.readByte()
                if (m0 != MAGIC_0 || m1 != MAGIC_1 || m2 != MAGIC_2) return null
                if (ver != VERSION) return null

                val fpLen = input.readUnsignedShort()
                if (fpLen <= 0 || fpLen > 256) return null
                val fpBytes = ByteArray(fpLen)
                input.readFully(fpBytes)
                val fp = fpBytes.toString(Charsets.US_ASCII)

                val onionLen = input.readUnsignedShort()
                if (onionLen <= 0 || onionLen > MAX_ONION_CHARS * 4) return null
                val onionBytes = ByteArray(onionLen)
                input.readFully(onionBytes)
                val onion = String(onionBytes, Charsets.UTF_8)

                val compLen = input.readInt()
                if (compLen <= 0 || compLen > MAX_COMPRESSED_BYTES) return null
                val compressed = ByteArray(compLen)
                input.readFully(compressed)

                val pubBytes = inflateZlib(compressed)
                val pubB64 = Base64.encodeToString(pubBytes, Base64.NO_WRAP)

                // Emit JSON compatible with JsonContactCodec.decodeContact()
                org.json.JSONObject().apply {
                    put("v", 1)
                    put("type", "contact")
                    put("fingerprint", fp)
                    put("onion", onion)
                    put("pub_b64", pubB64)
                    put("public_key_b64", pubB64)
                }.toString()
            }
        } catch (_: Throwable) {
            null
        }
    }

    // IMPORTANT: inflate zlib (nowrap=false). Default Deflater produces zlib.
    private fun inflateZlib(input: ByteArray): ByteArray {
        val inflater = Inflater(false)
        inflater.setInput(input)

        val bos = ByteArrayOutputStream(input.size * 2)
        val buf = ByteArray(4096)

        try {
            while (!inflater.finished()) {
                val n = try {
                    inflater.inflate(buf)
                } catch (_: Throwable) {
                    throw IllegalArgumentException("EC1_BAD_ZLIB")
                }

                if (n > 0) {
                    bos.write(buf, 0, n)
                } else {
                    if (inflater.needsInput()) break
                }
            }
        } finally {
            inflater.end()
        }

        val out = bos.toByteArray()
        if (out.isEmpty()) throw IllegalArgumentException("EC1_BAD_ZLIB_EMPTY")
        return out
    }

    // Minimal zlib deflate (nowrap=false), stable and small.
    private fun zlibDeflate(input: ByteArray): ByteArray {
        val deflater = java.util.zip.Deflater(java.util.zip.Deflater.BEST_COMPRESSION, false)
        deflater.setInput(input)
        deflater.finish()

        val out = ByteArrayOutputStream(input.size)
        val buf = ByteArray(4096)
        while (!deflater.finished()) {
            val n = deflater.deflate(buf)
            if (n > 0) out.write(buf, 0, n) else break
        }
        deflater.end()
        return out.toByteArray()
    }

    private fun sha256(b: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(b)
    }
}
