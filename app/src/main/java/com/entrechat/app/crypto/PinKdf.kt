/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import java.security.SecureRandom

object PinKdf {

    data class Params(
        val n: Int = 1 shl 15,
        val r: Int = 8,
        val p: Int = 1,
        val dkLen: Int = 32
    )

    data class Record(
        val salt: ByteArray,
        val params: Params,
        val pinVerifier: ByteArray // HMAC(dk, label)
    )

    private val rng = SecureRandom()

    // Domain separation label. Change if you ever change verifier scheme.
    private val VERIFIER_LABEL = "entrechat-pin-verifier-v1".toByteArray(Charsets.UTF_8)

    fun createRecord(pin: CharArray, params: Params = Params()): Record {
        val salt = ByteArray(16).also { rng.nextBytes(it) }
        val dk = derive(pin, salt, params)
        return try {
            val verifier = hmacSha256(dk, VERIFIER_LABEL)
            Record(salt = salt, params = params, pinVerifier = verifier)
        } finally {
            dk.fill(0)
        }
    }

    fun verify(pin: CharArray, record: Record): Boolean {
        val dk = derive(pin, record.salt, record.params)
        return try {
            val verifier = hmacSha256(dk, VERIFIER_LABEL)
            constantTimeEquals(verifier, record.pinVerifier).also {
                verifier.fill(0)
            }
        } finally {
            dk.fill(0)
        }
    }

    fun derive(pin: CharArray, salt: ByteArray, params: Params = Params()): ByteArray {
        val pinBytes = String(pin).toByteArray(Charsets.UTF_8)
        try {
            return SCrypt.generate(pinBytes, salt, params.n, params.r, params.p, params.dkLen)
        } finally {
            pinBytes.fill(0)
        }
    }

    private fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(msg, 0, msg.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
