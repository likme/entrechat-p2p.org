/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import android.util.Base64
import android.util.Log
import com.entrechat.app.network.CryptoResult
import com.entrechat.app.network.PgpEngine
import org.json.JSONObject

class CryptoServiceImpl(
    private val keyStoreProvider: KeyStoreProvider,
    private val pgpEngine: PgpEngine
) : CryptoService {

    companion object {
        private const val TAG = "CryptoService"
        private const val MAX_PGP_B64_CHARS = 2_000_000 // hard safety; real limit enforced higher in sender
    }

    override fun verifyAndDecryptEnvelope(
        senderFingerprint: String,
        recipientFingerprint: String,
        payloadBase64: String
    ): CryptoResult {

        val senderFp = senderFingerprint.trim().uppercase()
        val recipFp = recipientFingerprint.trim().uppercase()

        val senderPubRingBytes = keyStoreProvider.getPublicKeyRingBytesForFingerprint(senderFp)
            ?: run {
                Log.e(TAG, "verifyDecrypt NO_SENDER_PUB senderFp=${senderFp.take(8)}")
                return CryptoResult(success = false, plaintextJson = null, errorCode = "SIGNATURE_INVALID")
            }

        val recipientPriv = keyStoreProvider.getDecryptionPrivateKeyForFingerprint(recipFp)
            ?: run {
                Log.e(TAG, "verifyDecrypt NO_RECIP_DECRYPT_PRIV recipFp=${recipFp.take(8)}")
                return CryptoResult(success = false, plaintextJson = null, errorCode = "RECIPIENT_UNKNOWN")
            }

        val payloadClean = payloadBase64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        if (payloadClean.isBlank() || payloadClean.length > MAX_PGP_B64_CHARS) {
            Log.e(TAG, "verifyDecrypt BAD_PAYLOAD_B64 recipFp=${recipFp.take(8)} len=${payloadClean.length}")
            return CryptoResult(success = false, plaintextJson = null, errorCode = "BAD_REQUEST")
        }

        val encryptedBytes = try {
            Base64.decode(payloadClean, Base64.NO_WRAP)
        } catch (t: Exception) {
            Log.e(TAG, "verifyDecrypt BAD_B64 len=${payloadClean.length} msg=${t.message}", t)
            return CryptoResult(success = false, plaintextJson = null, errorCode = "BAD_REQUEST")
        }

        val plaintextBytes = try {
            Log.i(
                TAG,
                "verifyDecrypt decryptAndVerify senderFp=${senderFp.take(8)} recipFp=${recipFp.take(8)} encLen=${encryptedBytes.size}"
            )
            pgpEngine.decryptAndVerify(
                encryptedBytes = encryptedBytes,
                senderPublicKeyRingBytes = senderPubRingBytes,
                recipientPrivateKey = recipientPriv
            )
        } catch (t: SecurityException) {
            Log.e(TAG, "verifyDecrypt SIGNATURE_INVALID senderFp=${senderFp.take(8)} msg=${t.message}", t)
            encryptedBytes.fill(0)
            return CryptoResult(success = false, plaintextJson = null, errorCode = "SENDER_UNKNOWN")
        } catch (t: Exception) {
            Log.e(
                TAG,
                "verifyDecrypt DECRYPT_FAIL senderFp=${senderFp.take(8)} recipFp=${recipFp.take(8)} msg=${t.message}",
                t
            )
            encryptedBytes.fill(0)
            return CryptoResult(success = false, plaintextJson = null, errorCode = "CRYPTO_DECRYPT_FAIL")
        } finally {
            encryptedBytes.fill(0)
        }

        val plaintextJson = try {
            val s = String(plaintextBytes, Charsets.UTF_8)
            JSONObject(s)
        } catch (t: Exception) {
            Log.e(TAG, "verifyDecrypt JSON_PARSE_FAIL msg=${t.message}", t)
            plaintextBytes.fill(0)
            return CryptoResult(success = false, plaintextJson = null, errorCode = "PLAINTEXT_JSON_INVALID")
        } finally {
            plaintextBytes.fill(0)
        }

        return CryptoResult(success = true, plaintextJson = plaintextJson, errorCode = "")
    }

    override fun encryptAndSignEnvelope(
        senderFingerprint: String,
        recipientFingerprint: String,
        plaintextJsonUtf8: ByteArray
    ): CryptoResult {

        val senderFp = senderFingerprint.trim().uppercase()
        val recipFp = recipientFingerprint.trim().uppercase()

        val recipientPub = keyStoreProvider.getPublicKeyForFingerprint(recipFp)
            ?: run {
                Log.e(TAG, "encryptSign NO_RECIP_PUB recipFp=${recipFp.take(8)}")
                plaintextJsonUtf8.fill(0)
                return CryptoResult(success = false, plaintextJson = null, errorCode = "NO_RECIPIENT_KEY")
            }

        val senderPub = keyStoreProvider.getPublicKeyForFingerprint(senderFp)
            ?: run {
                Log.e(TAG, "encryptSign NO_SENDER_PUB senderFp=${senderFp.take(8)}")
                plaintextJsonUtf8.fill(0)
                return CryptoResult(success = false, plaintextJson = null, errorCode = "NO_SENDER_KEY")
            }

        val senderPriv = keyStoreProvider.getSigningPrivateKeyForFingerprint(senderFp)
            ?: run {
                Log.e(TAG, "encryptSign NO_SENDER_SIGN_PRIV senderFp=${senderFp.take(8)}")
                plaintextJsonUtf8.fill(0)
                return CryptoResult(success = false, plaintextJson = null, errorCode = "NO_SENDER_KEY")
            }

        val encryptedBytes = try {
            Log.i(
                TAG,
                "encryptSign encryptAndSign senderFp=${senderFp.take(8)} recipFp=${recipFp.take(8)} ptLen=${plaintextJsonUtf8.size}"
            )
            pgpEngine.encryptAndSign(
                plaintextBytes = plaintextJsonUtf8,
                recipientPublicKey = recipientPub,
                senderPublicKey = senderPub,   // allow local decrypt of OUT messages
                senderPrivateKey = senderPriv
            )
        } catch (t: Exception) {
            Log.e(
                TAG,
                "encryptSign ENCRYPT_FAIL senderFp=${senderFp.take(8)} recipFp=${recipFp.take(8)} ex=${t::class.java.name} msg=${t.message}",
                t
            )
            plaintextJsonUtf8.fill(0)
            return CryptoResult(success = false, plaintextJson = null, errorCode = "PGP_ENCRYPT_FAIL")
        } finally {
            plaintextJsonUtf8.fill(0)
        }

        val payloadB64 = try {
            Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        } catch (t: Exception) {
            Log.e(TAG, "encryptSign B64_ENCODE_FAIL encLen=${encryptedBytes.size} msg=${t.message}", t)
            encryptedBytes.fill(0)
            return CryptoResult(success = false, plaintextJson = null, errorCode = "CRYPTO_B64_FAIL")
        } finally {
            encryptedBytes.fill(0)
        }

        val payloadClean = payloadB64.trim()
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")

        if (payloadClean.isBlank()) {
            Log.e(TAG, "encryptSign EMPTY_PAYLOAD senderFp=${senderFp.take(8)} recipFp=${recipFp.take(8)}")
            return CryptoResult(success = false, plaintextJson = null, errorCode = "CRYPTO_B64_FAIL")
        }

        Log.i(TAG, "encryptSign OK payloadLen=${payloadClean.length} head=${payloadClean.take(16)}")
        return CryptoResult(
            success = true,
            plaintextJson = JSONObject(mapOf("payload_pgp" to payloadClean)),
            errorCode = ""
        )
    }
}
