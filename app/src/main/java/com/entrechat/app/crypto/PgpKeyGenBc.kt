/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.Date

object PgpKeyGenBc {

    data class KeyRings(
        val publicRing: PGPPublicKeyRing,
        val secretRing: PGPSecretKeyRing
    )

    /**
     * Generates:
     * - Primary RSA key: signing/certification
     * - Subkey RSA: encryption
     *
     * Secret ring is unencrypted (no passphrase) for MVP.
     * Stored-at-rest encryption is handled by BlobCryptoImpl.
     */
    fun generateRsa3072(userId: String): KeyRings {
        val rng = SecureRandom()

        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(3072, rng)

        val now = Date()

        val primaryKp = kpg.generateKeyPair()
        val encKp = kpg.generateKeyPair()

        val primary = JcaPGPKeyPair(PGPPublicKey.RSA_SIGN, primaryKp, now)
        val enc = JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, encKp, now)

        val digCalc: PGPDigestCalculator = JcaPGPDigestCalculatorProviderBuilder()
            .build()
            .get(HashAlgorithmTags.SHA256)


        val signerBuilder = JcaPGPContentSignerBuilder(
            primary.publicKey.algorithm,
            HashAlgorithmTags.SHA256
        )

        // No passphrase at the OpenPGP layer (BlobCrypto encrypts the ring at rest)
        val secretKeyEncryptor: PBESecretKeyEncryptor? = null
        // If you ever want PGP-level encryption too, use:
        // val secretKeyEncryptor = JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digCalc)
        //     .setProvider("BC")
        //     .build(charArrayOf(...))

        val keyRingGen = PGPKeyRingGenerator(
            PGPPublicKey.RSA_SIGN,
            primary,
            userId,
            digCalc,
            null,
            null,
            signerBuilder,
            secretKeyEncryptor
        )

        keyRingGen.addSubKey(enc)

        return KeyRings(
            publicRing = keyRingGen.generatePublicKeyRing(),
            secretRing = keyRingGen.generateSecretKeyRing()
        )
    }

    fun fingerprintHexUpper(primaryPublicKey: PGPPublicKey): String {
        val fp = primaryPublicKey.fingerprint
        val sb = StringBuilder(fp.size * 2)
        for (b in fp) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789ABCDEF"[v ushr 4])
            sb.append("0123456789ABCDEF"[v and 0x0F])
        }
        return sb.toString()
    }
}
