/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import java.io.ByteArrayInputStream
import java.lang.Long.toHexString
import java.util.Locale

object PgpKeyLoader {

    // ---------- Public keyrings ----------

    fun loadPublicKeyRingCollection(pubKeyBytes: ByteArray): PGPPublicKeyRingCollection {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(pubKeyBytes))
        return PGPPublicKeyRingCollection(input, BcKeyFingerprintCalculator())
    }

    fun loadPublicKey(pubKeyBytes: ByteArray): PGPPublicKey =
        loadEncryptionPublicKey(pubKeyBytes)


    /** Prefer encryption-capable subkey. Fallback: any encryption key. */
    fun loadEncryptionPublicKey(pubKeyBytes: ByteArray): PGPPublicKey {
        val collection = loadPublicKeyRingCollection(pubKeyBytes)

        // Pass 1: prefer subkeys (not master) that are encryption keys
        val ringIt1 = collection.keyRings
        while (ringIt1.hasNext()) {
            val ring = ringIt1.next()
            val keyIt = ring.publicKeys
            while (keyIt.hasNext()) {
                val k = keyIt.next()
                if (!k.isMasterKey && k.isEncryptionKey) return k
            }
        }

        // Pass 2: accept any encryption key (including master, rare)
        val ringIt2 = collection.keyRings
        while (ringIt2.hasNext()) {
            val ring = ringIt2.next()
            val keyIt = ring.publicKeys
            while (keyIt.hasNext()) {
                val k = keyIt.next()
                if (k.isEncryptionKey) return k
            }
        }

        throw PGPException("No encryption public key found in public keyring data")
    }

    /** For signature verification: choose exact key by keyID (supports signing subkeys). */
    fun findPublicKeyByKeyId(pubKeyBytes: ByteArray, keyId: Long): PGPPublicKey {
        val collection = loadPublicKeyRingCollection(pubKeyBytes)
        return collection.getPublicKey(keyId)
            ?: throw PGPException("No public key found for keyId=0x${toHexString(keyId)}")
    }

    // ---------- Secret keyrings ----------

    fun loadSecretKeyRing(secretRingBytes: ByteArray): PGPSecretKeyRing {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(secretRingBytes))
        return PGPSecretKeyRing(input, BcKeyFingerprintCalculator())
    }

    fun loadSecretKeyRingCollection(secretRingBytes: ByteArray): PGPSecretKeyRingCollection {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(secretRingBytes))
        return PGPSecretKeyRingCollection(input, BcKeyFingerprintCalculator())
    }

    /** Prefer encryption-capable subkey secret key. */
    fun findEncryptionSecretKey(ring: PGPSecretKeyRing): PGPSecretKey {
        // Pass 1: prefer subkeys (not master)
        val it1 = ring.secretKeys
        while (it1.hasNext()) {
            val k = it1.next()
            if (!k.publicKey.isMasterKey && k.publicKey.isEncryptionKey) return k
        }
        // Pass 2: any encryption key
        val it2 = ring.secretKeys
        while (it2.hasNext()) {
            val k = it2.next()
            if (k.publicKey.isEncryptionKey) return k
        }
        throw PGPException("No encryption secret key found in secret keyring")
    }

    /** Prefer signing-capable subkey secret key. */
    fun findSigningSecretKey(ring: PGPSecretKeyRing): PGPSecretKey {
        // Pass 1: prefer subkeys (not master)
        val it1 = ring.secretKeys
        while (it1.hasNext()) {
            val k = it1.next()
            if (!k.publicKey.isMasterKey && k.isSigningKey) return k
        }
        // Pass 2: any signing key
        val it2 = ring.secretKeys
        while (it2.hasNext()) {
            val k = it2.next()
            if (k.isSigningKey) return k
        }
        throw PGPException("No signing secret key found in secret keyring")
    }

    // ---------- Optional utilities ----------

    fun formatFingerprint(fp: ByteArray): String =
        fp.joinToString("") { "%02X".format(Locale.US, it) }

    fun keyIdHex(keyId: Long): String = "0x${toHexString(keyId)}"
}
