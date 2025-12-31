/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypt/decrypt arbitrary sensitive blobs (ex: encrypted private key ring).
 *
 * Recommended v1 behavior:
 * - Default: Keystore-only (NO_PIN)
 * - Optional: enable PIN to require unlockWithPin() for decrypt/encrypt
 *
 * This is independent from the DB passphrase provider.
 */
class BlobCryptoImpl(
    context: Context
) : BlobCrypto {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val rng = SecureRandom()

    @Volatile private var unlockedPinKey: ByteArray? = null
    @Volatile private var pinUnlocked: Boolean = false

    override fun encrypt(plaintext: ByteArray): ByteArray {
        val mode = getMode()

        val inner = when (mode) {
            Mode.NO_PIN -> plaintext.copyOf()
            Mode.PIN -> {
                if (!pinUnlocked) throw IllegalStateException("BlobCrypto locked: PIN required")
                val pinKey = unlockedPinKey ?: throw IllegalStateException("PIN key missing")
                wrapWithPinKey(plaintext, pinKey)
            }
        }

        try {
            val sealed = sealWithKeystore(inner)
            return packBlob(sealed, mode)
        } finally {
            inner.fill(0)
        }
    }

    override fun decrypt(encryptedBlob: ByteArray): ByteArray? {
        val (mode, sealedBytes) = unpackBlob(encryptedBlob) ?: return null

        val inner = try {
            unsealWithKeystore(sealedBytes)
        } catch (_: Exception) {
            return null
        }

        return try {
            when (mode) {
                Mode.NO_PIN -> inner
                Mode.PIN -> {
                    if (!pinUnlocked) {
                        inner.fill(0)
                        return null
                    }
                    val pinKey = unlockedPinKey ?: run {
                        inner.fill(0)
                        return null
                    }
                    val out = unwrapWithPinKey(inner, pinKey)
                    inner.fill(0)
                    out
                }
            }
        } catch (_: Exception) {
            inner.fill(0)
            null
        }
    }

    /**
     * One-time setup to enable PIN protection for blob crypto.
     * Stores PIN KDF record. Does not encrypt anything itself.
     */
    fun enablePin(pin: CharArray) {
        if (getMode() == Mode.PIN) return

        val record = PinKdf.createRecord(pin)
        prefs.edit()
            .putString(KEY_MODE, Mode.PIN.name)
            .putString(KEY_PIN_SALT, b64(record.salt))
            .putInt(KEY_PIN_N, record.params.n)
            .putInt(KEY_PIN_R, record.params.r)
            .putInt(KEY_PIN_P, record.params.p)
            .putInt(KEY_PIN_DKLEN, record.params.dkLen)
            .putString(KEY_PIN_VERIFIER, b64(record.pinVerifier))
            .apply()

        // Clean best-effort
        record.salt.fill(0)
        record.pinVerifier.fill(0)

        lock()
    }

    /**
     * Unlocks PIN mode for this process session.
     * Required before decrypt/encrypt when mode is PIN.
     */
    fun unlockWithPin(pin: CharArray): Boolean {
        if (getMode() != Mode.PIN) return true

        val record = loadPinRecord() ?: return false
        val ok = PinKdf.verify(pin, record)
        if (!ok) return false

        // Need an actual key for wrapping/unwrapping
        val key = PinKdf.derive(pin, record.salt, record.params)

        unlockedPinKey?.fill(0)
        unlockedPinKey = key
        pinUnlocked = true

        // Cleanup record buffers
        record.salt.fill(0)
        record.pinVerifier.fill(0)

        return true
    }

    /**
     * Drops PIN-derived key from memory.
     * Call onStop/onPause.
     */
    fun lock() {
        unlockedPinKey?.fill(0)
        unlockedPinKey = null
        pinUnlocked = false
    }

    /**
     * For wipe total: forget everything and destroy keystore key.
     */
    fun wipeAll() {
        lock()
        prefs.edit().clear().apply()
        deleteKeystoreKey()
    }

    // ---------------- Internals ----------------

    private enum class Mode { NO_PIN, PIN }

    private fun getMode(): Mode {
        val s = prefs.getString(KEY_MODE, null) ?: return Mode.NO_PIN
        return runCatching { Mode.valueOf(s) }.getOrDefault(Mode.NO_PIN)
    }

    private fun loadPinRecord(): PinKdf.Record? {
        val saltB64 = prefs.getString(KEY_PIN_SALT, null) ?: return null
        val verifierB64 = prefs.getString(KEY_PIN_VERIFIER, null) ?: return null

        val n = prefs.getInt(KEY_PIN_N, 1 shl 15)
        val r = prefs.getInt(KEY_PIN_R, 8)
        val p = prefs.getInt(KEY_PIN_P, 1)
        val dkLen = prefs.getInt(KEY_PIN_DKLEN, 32)

        return PinKdf.Record(
            salt = b64d(saltB64),
            params = PinKdf.Params(n = n, r = r, p = p, dkLen = dkLen),
            pinVerifier = b64d(verifierB64)
        )
    }

    // ----- PIN wrap (AES-GCM with derived key) -----

    private fun wrapWithPinKey(data: ByteArray, pinKey: ByteArray): ByteArray {
        val key = SecretKeySpec(pinKey, "AES")
        val iv = ByteArray(12).also { rng.nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(data)

        return packIvCt(iv, ct)
    }

    private fun unwrapWithPinKey(wrapped: ByteArray, pinKey: ByteArray): ByteArray {
        val (iv, ct) = unpackIvCt(wrapped)
        val key = SecretKeySpec(pinKey, "AES")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    // ----- Keystore seal/unseal (AES-GCM) -----

    private fun sealWithKeystore(plaintext: ByteArray): ByteArray {
        val key = getOrCreateKeystoreKey()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // IMPORTANT: do not provide an IV for ENCRYPT with Android Keystore GCM
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val ct = cipher.doFinal(plaintext)
        val iv = cipher.iv ?: throw IllegalStateException("Missing IV from cipher")

        return packIvCt(iv, ct)
    }


    private fun unsealWithKeystore(sealed: ByteArray): ByteArray {
        val (iv, ct) = unpackIvCt(sealed)
        val key = getOrCreateKeystoreKey()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    private fun getOrCreateKeystoreKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // Optional hardening:
            // .setUserAuthenticationRequired(true)
            // .setUserAuthenticationParameters(60, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun deleteKeystoreKey() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(KEYSTORE_ALIAS)) ks.deleteEntry(KEYSTORE_ALIAS)
    }

    // ----- Blob format helpers -----

    private fun packBlob(sealed: ByteArray, mode: Mode): ByteArray {
        val flags = when (mode) {
            Mode.NO_PIN -> 0x00
            Mode.PIN -> 0x01
        }
        val buf = ByteBuffer.allocate(2 + sealed.size)
        buf.put(VERSION)
        buf.put(flags.toByte())
        buf.put(sealed)
        return buf.array()
    }

    private fun unpackBlob(blob: ByteArray): Pair<Mode, ByteArray>? {
        if (blob.size < 3) return null
        if (blob[0] != VERSION) return null
        val flags = blob[1].toInt() and 0xFF
        val mode = if ((flags and 0x01) == 0x01) Mode.PIN else Mode.NO_PIN
        val sealed = blob.copyOfRange(2, blob.size)
        return mode to sealed
    }

    // iv|ct packing: [ivLen(1)] [iv] [ct]
    private fun packIvCt(iv: ByteArray, ct: ByteArray): ByteArray {
        require(iv.size in 12..16) { "IV length must be 12..16" }
        val buf = ByteBuffer.allocate(1 + iv.size + ct.size)
        buf.put(iv.size.toByte())
        buf.put(iv)
        buf.put(ct)
        return buf.array()
    }

    private fun unpackIvCt(blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.isNotEmpty()) { "Empty blob" }
        val ivLen = blob[0].toInt() and 0xFF
        require(ivLen in 12..16) { "Bad IV length" }
        require(blob.size > 1 + ivLen) { "Bad blob" }
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ct = blob.copyOfRange(1 + ivLen, blob.size)
        return iv to ct
    }

    private fun b64(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

    private fun b64d(s: String): ByteArray =
        android.util.Base64.decode(s, android.util.Base64.NO_WRAP)

    companion object {
        private const val PREFS_NAME = "entrechat_blob_crypto"
        private const val KEYSTORE_ALIAS = "entrechat_blob_keystore_aes"
        private const val VERSION: Byte = 0x01

        private const val KEY_MODE = "mode"
        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_PIN_VERIFIER = "pin_verifier"
        private const val KEY_PIN_N = "pin_n"
        private const val KEY_PIN_R = "pin_r"
        private const val KEY_PIN_P = "pin_p"
        private const val KEY_PIN_DKLEN = "pin_dklen"
    }
}

/**
 * Contract used by KeyStoreProviderImpl and identity storage.
 */
interface BlobCrypto {
    fun encrypt(plaintext: ByteArray): ByteArray
    fun decrypt(encryptedBlob: ByteArray): ByteArray?
}
