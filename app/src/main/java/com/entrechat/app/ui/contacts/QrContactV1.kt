/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.contacts

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream
import kotlin.math.ceil

object QrContactV1 {

    private const val PREFIX_SINGLE = "ec1|"

    private const val MAGIC_0: Byte = 'E'.code.toByte()
    private const val MAGIC_1: Byte = 'C'.code.toByte()
    private const val MAGIC_2: Byte = '1'.code.toByte()
    private const val VERSION: Byte = 1

    private const val MAX_SINGLE_QR_CHARS = 3000

    private const val MAX_TOTAL_PARTS = 10
    private const val MAX_JOINED_B64_LEN = 256_000

    // Keep these aligned with JsonContactCodec.MAX_PUBLIC_KEY_BYTES (currently 32 KB)
    private const val MAX_PUBKEY_BYTES = 32 * 1024
    private const val MAX_COMPRESSED_BYTES = 64 * 1024

    private const val MAX_ONION_CHARS = 128

    data class Header(
        val fingerprint: String,
        val onion: String,
        val sha8: String,
        val totalParts: Int
    )

    data class Part(
        val sha8: String,
        val index: Int,
        val totalParts: Int,
        val chunkB64: String
    )

    sealed class ParseLineResult {
        data class SingleLine(val contact: DecodedContact) : ParseLineResult()
        data class HeaderLine(val header: Header) : ParseLineResult()
        data class PartLine(val part: Part) : ParseLineResult()
        data class Ignore(val reason: String) : ParseLineResult()
    }

    data class MergeState(
        val header: Header? = null,
        val parts: MutableMap<Int, String> = linkedMapOf(),
        val single: DecodedContact? = null
    ) {
        fun isComplete(): Boolean {
            if (single != null) return true
            val h = header ?: return false
            if (h.totalParts <= 0) return false
            return parts.size == h.totalParts && (1..h.totalParts).all { parts.containsKey(it) }
        }
    }

    data class DecodedContact(
        val fingerprint: String,
        val onion: String,
        val publicKeyB64: String
    )

    fun encodeToSingleQrLine(
        fingerprint: String,
        onion: String,
        pubkeyBytes: ByteArray
    ): String {
        val fpCanon = fingerprint.trim().replace("\\s+".toRegex(), "").uppercase()
        require(fpCanon.matches(Regex("^[0-9A-F]{40}$"))) { "BAD_FINGERPRINT" }


        val onionCanon = onion.trim()
        require(onionCanon.isNotBlank()) { "BAD_ONION" }
        require(onionCanon.length <= MAX_ONION_CHARS) { "BAD_ONION" }

        require(pubkeyBytes.isNotEmpty()) { "BAD_PUBKEY" }
        require(pubkeyBytes.size <= MAX_PUBKEY_BYTES) { "PUBKEY_TOO_LARGE" }

        val compressedPub = deflate(pubkeyBytes)
        require(compressedPub.size <= MAX_COMPRESSED_BYTES) { "PUBKEY_TOO_LARGE" }

        val payloadNoCk = ByteArrayOutputStream().use { baos ->
            DataOutputStream(baos).use { out ->
                out.writeByte(MAGIC_0.toInt())
                out.writeByte(MAGIC_1.toInt())
                out.writeByte(MAGIC_2.toInt())
                out.writeByte(VERSION.toInt())

                val fpBytes = fpCanon.toByteArray(Charsets.US_ASCII)
                out.writeShort(fpBytes.size)
                out.write(fpBytes)

                val onionBytes = onionCanon.lowercase().toByteArray(Charsets.UTF_8)
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
        val out = PREFIX_SINGLE + b64url

        require(out.length <= MAX_SINGLE_QR_CHARS) { "QR_TOO_LARGE" }
        return out
    }

    /**
     * Legacy multi-part encoder (kept only for backward compatibility).
     * Do not use in new UI flows.
     */
    fun encodeToQrLines3(
        fingerprint: String,
        onion: String,
        pubkeyBytes: ByteArray
    ): List<String> {
        require(pubkeyBytes.isNotEmpty()) { "BAD_PUBKEY" }
        require(pubkeyBytes.size <= MAX_PUBKEY_BYTES) { "PUBKEY_TOO_LARGE" }

        val compressed = deflate(pubkeyBytes)
        require(compressed.size <= MAX_COMPRESSED_BYTES) { "PUBKEY_TOO_LARGE" }

        val b64 = Base64.encodeToString(compressed, Base64.NO_WRAP)

        val sha8 = sha256Hex(b64.toByteArray(Charsets.UTF_8)).substring(0, 8)
        val total = 3

        val header = "ec1h|$fingerprint|$onion|$sha8|$total"

        val chunks = splitStringIntoParts(b64, total)
        val p1 = "ec1p|$total|$sha8|1|${chunks[0]}"
        val p2 = "ec1p|$total|$sha8|2|${chunks[1]}"
        val p3 = "ec1p|$total|$sha8|3|${chunks[2]}"

        return listOf(header, p1, p2, p3)
    }

    fun parseLine(line: String): ParseLineResult {
        val s = line.trim()
        if (s.isBlank()) return ParseLineResult.Ignore("blank")

        if (s.startsWith(PREFIX_SINGLE, ignoreCase = true)) {
            val b64 = s.substring(PREFIX_SINGLE.length).trim()
            if (b64.isBlank()) return ParseLineResult.Ignore("empty_single")
            if (b64.length > MAX_JOINED_B64_LEN) return ParseLineResult.Ignore("single_too_large")
            val decoded = decodeSinglePayload(b64) ?: return ParseLineResult.Ignore("bad_single")
            return ParseLineResult.SingleLine(decoded)
        }

        if (s.startsWith("ec1h|", ignoreCase = true)) {
            val parts = s.split("|")
            if (parts.size != 5) return ParseLineResult.Ignore("bad_header_parts")
            val fp = parts[1].trim()
            val onion = parts[2].trim()
            val sha8 = parts[3].trim()
            val total = parts[4].trim().toIntOrNull() ?: return ParseLineResult.Ignore("bad_total")
            if (fp.isBlank()) return ParseLineResult.Ignore("missing_fp")
            if (sha8.length != 8) return ParseLineResult.Ignore("bad_sha8")
            if (total <= 0 || total > MAX_TOTAL_PARTS) return ParseLineResult.Ignore("bad_total_range")
            return ParseLineResult.HeaderLine(Header(fp, onion, sha8, total))
        }

        if (s.startsWith("ec1p|", ignoreCase = true)) {
            val parts = s.split("|", limit = 5)
            if (parts.size != 5) return ParseLineResult.Ignore("bad_part_parts")
            val total = parts[1].trim().toIntOrNull() ?: return ParseLineResult.Ignore("bad_total")
            val sha8 = parts[2].trim()
            val idx = parts[3].trim().toIntOrNull() ?: return ParseLineResult.Ignore("bad_index")
            val chunk = parts[4].trim()
            if (sha8.length != 8) return ParseLineResult.Ignore("bad_sha8")
            if (total <= 0 || total > MAX_TOTAL_PARTS) return ParseLineResult.Ignore("bad_total_range")
            if (idx <= 0 || idx > total) return ParseLineResult.Ignore("bad_index_range")
            if (chunk.isBlank()) return ParseLineResult.Ignore("empty_chunk")
            return ParseLineResult.PartLine(Part(sha8, idx, total, chunk))
        }

        return ParseLineResult.Ignore("unknown_prefix")
    }

    fun mergeLine(state: MergeState, line: String): MergeState {
        return when (val r = parseLine(line)) {
            is ParseLineResult.SingleLine -> state.copy(single = r.contact)
            is ParseLineResult.HeaderLine -> {
                val existing = state.header
                if (existing != null && existing.sha8 != r.header.sha8) state else state.copy(header = r.header)
            }
            is ParseLineResult.PartLine -> {
                val h = state.header
                if (h != null && h.sha8 != r.part.sha8) return state
                if (h != null && h.totalParts != r.part.totalParts) return state
                state.parts[r.part.index] = r.part.chunkB64
                state
            }
            is ParseLineResult.Ignore -> state
        }
    }

    fun tryDecodeContact(state: MergeState): DecodedContact? {
        state.single?.let { return it }

        val h = state.header ?: return null
        if (!state.isComplete()) return null

        val joined = (1..h.totalParts).joinToString(separator = "") { idx ->
            state.parts[idx].orEmpty()
        }

        if (joined.length > MAX_JOINED_B64_LEN) return null

        val computedSha8 = sha256Hex(joined.toByteArray(Charsets.UTF_8)).substring(0, 8)
        if (computedSha8 != h.sha8) return null

        val compressed = try {
            val raw = Base64.decode(joined, Base64.NO_WRAP)
            if (raw.size > MAX_COMPRESSED_BYTES) return null
            raw
        } catch (_: Throwable) {
            return null
        }

        val pubkey = try {
            val out = inflate(compressed)
            if (out.size > MAX_PUBKEY_BYTES) return null
            out
        } catch (_: Throwable) {
            return null
        }

        val publicKeyB64 = Base64.encodeToString(pubkey, Base64.NO_WRAP)
        return DecodedContact(
            fingerprint = h.fingerprint,
            onion = h.onion,
            publicKeyB64 = publicKeyB64
        )
    }

    private fun decodeSinglePayload(b64url: String): DecodedContact? {
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
                if (onion.length > MAX_ONION_CHARS) return null
                if (onion.isBlank()) return null

                val compLen = input.readInt()
                if (compLen <= 0 || compLen > MAX_COMPRESSED_BYTES) return null
                val compressed = ByteArray(compLen)
                input.readFully(compressed)

                if (input.available() != 0) return null

                val pub = inflate(compressed)
                if (pub.size > MAX_PUBKEY_BYTES) return null
                val pubB64 = Base64.encodeToString(pub, Base64.NO_WRAP)

                DecodedContact(fingerprint = fp, onion = onion, publicKeyB64 = pubB64)
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun splitStringIntoParts(s: String, parts: Int): List<String> {
        if (parts <= 1) return listOf(s)
        val len = s.length
        val chunkSize = ceil(len / parts.toDouble()).toInt().coerceAtLeast(1)
        val out = ArrayList<String>(parts)
        var i = 0
        while (i < len) {
            val end = (i + chunkSize).coerceAtMost(len)
            out.add(s.substring(i, end))
            i = end
        }
        while (out.size < parts) out.add("")
        return out
    }

    private fun sha256Hex(b: ByteArray): String {
        val d = sha256(b)
        val sb = StringBuilder(d.size * 2)
        for (x in d) {
            val v = x.toInt() and 0xff
            if (v < 16) sb.append('0')
            sb.append(v.toString(16))
        }
        return sb.toString()
    }

    private fun sha256(b: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(b)
    }

    private fun deflate(input: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        DeflaterOutputStream(baos).use { it.write(input) }
        return baos.toByteArray()
    }

    private fun inflate(input: ByteArray): ByteArray {
        val bais = ByteArrayInputStream(input)
        InflaterInputStream(bais).use { inflater ->
            val baos = ByteArrayOutputStream()
            val buf = ByteArray(8 * 1024)
            while (true) {
                val n = inflater.read(buf)
                if (n <= 0) break
                baos.write(buf, 0, n)
            }
            return baos.toByteArray()
        }
    }
}
