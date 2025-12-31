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
 * Recommended SQLCipher passphrase provider for Entrechat v1.
 *
 * Storage:
 * - Generates a 32-byte random passphrase
 * - Protects it with Android Keystore (AES-GCM)
 * - Optional: also wraps it with a PIN-derived key (scrypt) before Keystore sealing.
 *
 * Usage:
 * - If PIN is not enabled: call getPassphrase()
 * - If PIN is enabled: call unlockWithPin(pin) once per session, then getPassphrase()
 */
class KeystorePinDbPassphraseProvider(
    context: Context
) : DbPassphraseProvider {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val rng = SecureRandom()

    @Volatile private var cachedPassphrase: ByteArray? = null
    @Volatile private var pinUnlocked: Boolean = false

    override fun getPassphrase(): ByteArray {
        cachedPassphrase?.let { return it }

        val mode = getMode()

        // If PIN mode, require unlock.
        if (mode == Mode.PIN && !pinUnlocked) {
            throw IllegalStateException("DB locked: PIN required")
        }

        // Ensure sealed blob exists.
        if (!prefs.contains(KEY_SEALED_BLOB)) {
            val pass = randomPassphrase32()

            when (mode) {
                Mode.NO_PIN -> {
                    val sealed = sealWithKeystore(pass)
                    saveSealedOnly(sealed)
                }
                Mode.PIN -> {
                    // PIN mode should be initialized via enablePin() first.
                    pass.fill(0)
                    throw IllegalStateException("PIN mode not initialized")
                }
            }

            pass.fill(0)
        }

        // Load sealed blob and decrypt.
        val sealed = prefs.getString(KEY_SEALED_BLOB, null)
            ?: throw IllegalStateException("Missing sealed blob")

        val innerBytes = unsealWithKeystore(decodeB64(sealed))

        val passphrase = when (mode) {
            Mode.NO_PIN -> innerBytes
            Mode.PIN -> {
                // innerBytes = pinWrapped(passphrase), decrypt with cached pin key.
                val pinKey = cachedPinKey ?: run {
                    innerBytes.fill(0)
                    throw IllegalStateException("PIN key missing in memory")
                }
                val out = unwrapWithPinKey(innerBytes, pinKey)
                innerBytes.fill(0)
                out
            }
        }

        cachedPassphrase = passphrase
        return passphrase
    }

    /**
     * Enables PIN protection. One-time setup. After this, app requires PIN to unlock DB key.
     *
     * It migrates from NO_PIN (or fresh) to PIN mode.
     */
    fun enablePin(pin: CharArray) {
        if (getMode() == Mode.PIN) return

        val pass = if (prefs.contains(KEY_SEALED_BLOB)) {
            // Existing passphrase sealed with keystore in NO_PIN mode.
            val sealed = prefs.getString(KEY_SEALED_BLOB, null)
                ?: throw IllegalStateException("Missing sealed blob")
            unsealWithKeystore(decodeB64(sealed))
        } else {
            randomPassphrase32()
        }

        val record = PinKdf.createRecord(pin)
        val pinKey = PinKdf.derive(pin, record.salt, record.params)


        val wrapped = wrapWithPinKey(pass, pinKey)
        val sealedWrapped = sealWithKeystore(wrapped)

        // Persist PIN record and sealed blob
        prefs.edit()
            .putString(KEY_MODE, Mode.PIN.name)
            .putString(KEY_SEALED_BLOB, encodeB64(sealedWrapped))
            .putString(KEY_PIN_SALT, encodeB64(record.salt))
            .putInt(KEY_PIN_N, record.params.n)
            .putInt(KEY_PIN_R, record.params.r)
            .putInt(KEY_PIN_P, record.params.p)
            .putInt(KEY_PIN_DKLEN, record.params.dkLen)
            .putString(KEY_PIN_VERIFIER, encodeB64(record.pinVerifier))
            .apply()

        // Clean
        pass.fill(0)
        wrapped.fill(0)
        sealedWrapped.fill(0)
        record.salt.fill(0)
        record.pinVerifier.fill(0)

        pinKey.fill(0)

        lock()
    }

    /**
     * Unlocks PIN mode for this process session.
     * Keeps only a derived key in memory (best-effort) and a cached passphrase once retrieved.
     */
    fun unlockWithPin(pin: CharArray): Boolean {
        if (getMode() != Mode.PIN) return true

        val record = loadPinRecord() ?: return false
        val ok = PinKdf.verify(pin, record)
        if (!ok) return false

        // Derive key again (PinKdf.verify zeroizes its dk; we need a key to unwrap).
        val pinKey = PinKdf.derive(pin, record.salt, record.params)

        cachedPinKey?.fill(0)
        cachedPinKey = pinKey
        pinUnlocked = true

        // Do not cache passphrase here; it will be decrypted on demand by getPassphrase().
        return true
    }

    /**
     * Locks: drops cached keys and passphrase from memory.
     * Call onStop/onPause.
     */
    fun lock() {
        cachedPassphrase?.fill(0)
        cachedPassphrase = null

        cachedPinKey?.fill(0)
        cachedPinKey = null

        pinUnlocked = false
    }

    /**
     * Wipes DB key material. Use for "wipe total".
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

    private fun saveSealedOnly(sealed: ByteArray) {
        prefs.edit()
            .putString(KEY_MODE, Mode.NO_PIN.name)
            .putString(KEY_SEALED_BLOB, encodeB64(sealed))
            .apply()
        sealed.fill(0)
    }

    private fun randomPassphrase32(): ByteArray =
        ByteArray(32).also { rng.nextBytes(it) }

    // ----- PIN record storage -----

    private fun loadPinRecord(): PinKdf.Record? {
        val saltB64 = prefs.getString(KEY_PIN_SALT, null) ?: return null
        val verifierB64 = prefs.getString(KEY_PIN_VERIFIER, null) ?: return null

        val n = prefs.getInt(KEY_PIN_N, 1 shl 15)
        val r = prefs.getInt(KEY_PIN_R, 8)
        val p = prefs.getInt(KEY_PIN_P, 1)
        val dkLen = prefs.getInt(KEY_PIN_DKLEN, 32)

        val salt = decodeB64(saltB64)
        val verifier = decodeB64(verifierB64)

        return PinKdf.Record(
            salt = salt,
            params = PinKdf.Params(n = n, r = r, p = p, dkLen = dkLen),
            pinVerifier = verifier
        )
    }

    // ----- PIN wrap: AES-GCM with derived key -----

    private fun wrapWithPinKey(passphrase: ByteArray, pinKey: ByteArray): ByteArray {
        val key = SecretKeySpec(pinKey, "AES")
        val iv = ByteArray(12).also { rng.nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(passphrase)

        return pack(iv, ct)
    }

    private fun unwrapWithPinKey(wrapped: ByteArray, pinKey: ByteArray): ByteArray {
        val (iv, ct) = unpack(wrapped)
        val key = SecretKeySpec(pinKey, "AES")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    // ----- Keystore seal/unseal: AES-GCM -----

    private fun sealWithKeystore(plaintext: ByteArray): ByteArray {
        val key = getOrCreateKeystoreKey()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // IMPORTANT: do not provide an IV for ENCRYPT with Android Keystore GCM
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val ct = cipher.doFinal(plaintext)
        val iv = cipher.iv ?: throw IllegalStateException("Missing IV from cipher")

        return pack(iv, ct)
    }


    private fun unsealWithKeystore(sealed: ByteArray): ByteArray {
        val (iv, ct) = unpack(sealed)
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
        if (ks.containsAlias(KEYSTORE_ALIAS)) {
            ks.deleteEntry(KEYSTORE_ALIAS)
        }
    }

    // ----- blob packing helpers: [ivLen(1)] [iv] [ct] -----

    private fun pack(iv: ByteArray, ct: ByteArray): ByteArray {
        require(iv.size in 12..16) { "IV length must be 12..16" }
        val buf = ByteBuffer.allocate(1 + iv.size + ct.size)
        buf.put(iv.size.toByte())
        buf.put(iv)
        buf.put(ct)
        return buf.array()
    }

    private fun unpack(blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.isNotEmpty()) { "Empty blob" }
        val ivLen = blob[0].toInt() and 0xFF
        require(ivLen in 12..16) { "Bad IV length" }
        require(blob.size > 1 + ivLen) { "Bad blob" }

        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ct = blob.copyOfRange(1 + ivLen, blob.size)
        return iv to ct
    }

    // ----- base64 (android.util.Base64 for Android) -----

    private fun encodeB64(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

    private fun decodeB64(s: String): ByteArray =
        android.util.Base64.decode(s, android.util.Base64.NO_WRAP)

    companion object {
        private const val PREFS_NAME = "entrechat_db_key"
        private const val KEYSTORE_ALIAS = "entrechat_db_keystore_aes"

        private const val KEY_MODE = "mode"
        private const val KEY_SEALED_BLOB = "sealed_blob"

        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_PIN_VERIFIER = "pin_verifier"
        private const val KEY_PIN_N = "pin_n"
        private const val KEY_PIN_R = "pin_r"
        private const val KEY_PIN_P = "pin_p"
        private const val KEY_PIN_DKLEN = "pin_dklen"
    }

    // cached PIN-derived key (only while unlocked)
    @Volatile private var cachedPinKey: ByteArray? = null
}
