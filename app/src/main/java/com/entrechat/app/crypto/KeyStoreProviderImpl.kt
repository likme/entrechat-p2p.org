/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import android.util.Log
import com.entrechat.app.db.ContactDao
import com.entrechat.app.db.IdentityDao
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import java.security.Provider

class KeyStoreProviderImpl(
    private val contactDao: ContactDao,
    private val identityDao: IdentityDao,
    private val blobCrypto: BlobCrypto,
    // Explicit embedded provider. Do not rely on Android's stub "BC".
    private val bc: Provider = BouncyCastleProvider()
) : KeyStoreProvider {

    companion object {
        private const val TAG = "KeyStoreProvider"
        private const val ALGO_RSA_ENCRYPT_ONLY = 2
    }

    override fun getPublicKeyForFingerprint(fingerprint: String): PgpPublicKey? {
        val fp = fingerprint.trim().uppercase()

        val contact = contactDao.getByFingerprint(fp)
        if (contact != null) {
            val pubKey = try { PgpKeyLoader.loadPublicKey(contact.publicKeyBytes) } catch (_: Exception) { return null }
            return PgpPublicKey(pubKey)
        }

        val identity = identityDao.getByFingerprint(fp) ?: return null
        val pubKey = try { PgpKeyLoader.loadPublicKey(identity.publicKeyBytes) } catch (_: Exception) { return null }
        return PgpPublicKey(pubKey)
    }

    override fun getPublicKeyRingBytesForFingerprint(fingerprint: String): ByteArray? {
        val fp = fingerprint.trim().uppercase()

        val contact = contactDao.getByFingerprint(fp)
        if (contact != null) {
            return contact.publicKeyBytes.takeIf { it.isNotEmpty() }
        }

        val identity = identityDao.getByFingerprint(fp) ?: return null
        return identity.publicKeyBytes.takeIf { it.isNotEmpty() }
    }

    override fun getDecryptionPrivateKeyForFingerprint(fingerprint: String): PgpPrivateKey? {
        val fp = fingerprint.trim().uppercase()
        val identity = identityDao.getByFingerprint(fp) ?: return null

        val ringBytes = blobCrypto.decrypt(identity.privateKeyBlobEncrypted) ?: return null

        try {
            val ring = PgpKeyLoader.loadSecretKeyRing(ringBytes)

            val secretKey = try {
                PgpKeyLoader.findEncryptionSecretKey(ring)
            } catch (t: Throwable) {
                Log.e(TAG, "findEncryptionSecretKey failed fp=${fp.take(8)} msg=${t.message}", t)
                null
            } ?: run {
                Log.e(TAG, "NO_DECRYPTION_SECRET_KEY fp=${fp.take(8)}")
                return null
            }

            Log.i(
                TAG,
                "selected DECRYPT key fp=${fp.take(8)} keyId=${java.lang.Long.toHexString(secretKey.keyID)} algo=${secretKey.publicKey.algorithm}"
            )

            val decryptor = JcePBESecretKeyDecryptorBuilder()
                .setProvider(bc)
                .build(CharArray(0))

            val privateKey = secretKey.extractPrivateKey(decryptor)
            return PgpPrivateKey(privateKey)
        } catch (t: PGPException) {
            Log.e(TAG, "getDecryptionPrivateKey PGPException fp=${fp.take(8)} msg=${t.message}", t)
            return null
        } finally {
            ringBytes.fill(0)
        }
    }

    override fun getSigningPrivateKeyForFingerprint(fingerprint: String): PgpPrivateKey? {
        val fp = fingerprint.trim().uppercase()
        val identity = identityDao.getByFingerprint(fp) ?: return null

        val ringBytes = blobCrypto.decrypt(identity.privateKeyBlobEncrypted) ?: return null

        try {
            val ring = PgpKeyLoader.loadSecretKeyRing(ringBytes)

            val secretKey = findSigningSecretKey(ring)
                ?: run {
                    Log.e(TAG, "NO_SIGNING_SECRET_KEY fp=${fp.take(8)}")
                    return null
                }

            Log.i(
                TAG,
                "selected SIGN key fp=${fp.take(8)} keyId=${java.lang.Long.toHexString(secretKey.keyID)} algo=${secretKey.publicKey.algorithm} isSigning=${secretKey.isSigningKey}"
            )

            val decryptor = JcePBESecretKeyDecryptorBuilder()
                .setProvider(bc)
                .build(CharArray(0))

            val privateKey = secretKey.extractPrivateKey(decryptor)
            return PgpPrivateKey(privateKey)
        } catch (t: PGPException) {
            Log.e(TAG, "getSigningPrivateKey PGPException fp=${fp.take(8)} msg=${t.message}", t)
            return null
        } finally {
            ringBytes.fill(0)
        }
    }

    private fun findSigningSecretKey(ring: PGPSecretKeyRing): PGPSecretKey? {
        var fallbackNonEncryptOnly: PGPSecretKey? = null

        val it = ring.secretKeys
        while (it.hasNext()) {
            val sk = it.next() as PGPSecretKey
            val algo = sk.publicKey.algorithm

            if (sk.isSigningKey && algo != ALGO_RSA_ENCRYPT_ONLY) return sk
            if (algo != ALGO_RSA_ENCRYPT_ONLY && fallbackNonEncryptOnly == null) fallbackNonEncryptOnly = sk
        }
        return fallbackNonEncryptOnly
    }
}
