/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import com.entrechat.app.network.PgpEngine
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.Provider
import java.security.SecureRandom
import java.util.Date

data class PgpPublicKey(val key: PGPPublicKey)
data class PgpPrivateKey(val key: PGPPrivateKey)

class PgpEngineBc(
    /**
     * Important:
     * - Must NOT rely on Android's built-in "BC" provider (stub).
     * - Use an explicit Provider instance (embedded bcprov).
     */
    private val bc: Provider = BouncyCastleProvider()
) : PgpEngine {

    private fun secureRandom(): SecureRandom = SecureRandom()

    override fun decryptAndVerify(
        encryptedBytes: ByteArray,
        senderPublicKeyRingBytes: ByteArray,
        recipientPrivateKey: PgpPrivateKey
    ): ByteArray {
        val pgpIn = PGPUtil.getDecoderStream(ByteArrayInputStream(encryptedBytes))
        val f0 = JcaPGPObjectFactory(pgpIn)

        val encList = (f0.nextObject() as? PGPEncryptedDataList)
            ?: (f0.nextObject() as? PGPEncryptedDataList)
            ?: throw PGPException("No PGPEncryptedDataList")

        val pbe = findPkEncryptedData(encList, recipientPrivateKey.key.keyID)
            ?: throw PGPException("No matching recipient key in encrypted data")

        val decryptorFactory = JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider(bc)
            .build(recipientPrivateKey.key)

        val clearStream = pbe.getDataStream(decryptorFactory)
        val f1 = JcaPGPObjectFactory(clearStream)

        val first = f1.nextObject() ?: throw PGPException("Empty decrypted content")

        return if (first is PGPCompressedData) {
            val msgFactory = JcaPGPObjectFactory(first.dataStream)
            decryptAndVerifyParsed(msgFactory, senderPublicKeyRingBytes, pbe)
        } else {
            decryptAndVerifyParsed(first, f1, senderPublicKeyRingBytes, pbe)
        }
    }

    private fun decryptAndVerifyParsed(
        factory: JcaPGPObjectFactory,
        senderPublicKeyRingBytes: ByteArray,
        pbe: PGPPublicKeyEncryptedData
    ): ByteArray {
        val onePassList = factory.nextObject() as? PGPOnePassSignatureList
            ?: throw PGPException("Expected PGPOnePassSignatureList")
        val literal = factory.nextObject() as? PGPLiteralData
            ?: throw PGPException("Expected PGPLiteralData")
        val sigList = factory.nextObject() as? PGPSignatureList
            ?: throw PGPException("Expected PGPSignatureList")

        return verifyAndCollect(onePassList, literal, sigList, senderPublicKeyRingBytes, pbe)
    }

    private fun decryptAndVerifyParsed(
        firstObj: Any,
        factory: JcaPGPObjectFactory,
        senderPublicKeyRingBytes: ByteArray,
        pbe: PGPPublicKeyEncryptedData
    ): ByteArray {
        val onePassList = firstObj as? PGPOnePassSignatureList
            ?: throw PGPException("Expected PGPOnePassSignatureList")
        val literal = factory.nextObject() as? PGPLiteralData
            ?: throw PGPException("Expected PGPLiteralData")
        val sigList = factory.nextObject() as? PGPSignatureList
            ?: throw PGPException("Expected PGPSignatureList")

        return verifyAndCollect(onePassList, literal, sigList, senderPublicKeyRingBytes, pbe)
    }

    private fun verifyAndCollect(
        onePassList: PGPOnePassSignatureList,
        literal: PGPLiteralData,
        sigList: PGPSignatureList,
        senderPublicKeyRingBytes: ByteArray,
        pbe: PGPPublicKeyEncryptedData
    ): ByteArray {
        val onePass = onePassList[0]
        val sig = sigList[0]

        val verifyKey = PgpKeyLoader.findPublicKeyByKeyId(senderPublicKeyRingBytes, sig.keyID)

        onePass.init(
            JcaPGPContentVerifierBuilderProvider().setProvider(bc),
            verifyKey
        )

        val out = ByteArrayOutputStream()
        literal.inputStream.use { input ->
            val buf = ByteArray(8 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                onePass.update(buf, 0, n)
                out.write(buf, 0, n)
            }
        }

        if (!onePass.verify(sig)) {
            throw SecurityException(
                "PGP signature invalid (sigKeyId=0x${java.lang.Long.toHexString(sig.keyID)}, " +
                    "verifyKeyId=0x${java.lang.Long.toHexString(verifyKey.keyID)})"
            )
        }

        if (pbe.isIntegrityProtected && !pbe.verify()) {
            throw SecurityException("PGP integrity check failed")
        }

        return out.toByteArray()
    }

    private fun findPkEncryptedData(
        encList: PGPEncryptedDataList,
        recipientKeyId: Long
    ): PGPPublicKeyEncryptedData? {
        val it1 = encList.encryptedDataObjects
        while (it1.hasNext()) {
            val o = it1.next()
            if (o is PGPPublicKeyEncryptedData && o.keyID == recipientKeyId) return o
        }
        val it2 = encList.encryptedDataObjects
        while (it2.hasNext()) {
            val o = it2.next()
            if (o is PGPPublicKeyEncryptedData) return o
        }
        return null
    }

    override fun encryptAndSign(
        plaintextBytes: ByteArray,
        recipientPublicKey: PgpPublicKey,
        senderPublicKey: PgpPublicKey,
        senderPrivateKey: PgpPrivateKey
    ): ByteArray {


        // 1) Sign + literal inside compression
        val signedBytes: ByteArray = run {
            val signedOut = ByteArrayOutputStream()
            val compGen = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
            compGen.open(signedOut).use { compOut ->
                val pgpOut = BCPGOutputStream(compOut)

                val senderAlgo = senderPrivateKey.key.publicKeyPacket.algorithm
                val sigGen = PGPSignatureGenerator(
                    JcaPGPContentSignerBuilder(senderAlgo, HashAlgorithmTags.SHA256)
                        .setProvider(bc)
                )
                sigGen.init(PGPSignature.BINARY_DOCUMENT, senderPrivateKey.key)

                sigGen.generateOnePassVersion(false).encode(pgpOut)

                val litGen = PGPLiteralDataGenerator()
                litGen.open(
                    pgpOut,
                    PGPLiteralData.BINARY,
                    "msg",
                    plaintextBytes.size.toLong(),
                    Date()
                ).use { litOut ->
                    var off = 0
                    val buf = ByteArray(8 * 1024)
                    while (off < plaintextBytes.size) {
                        val n = minOf(buf.size, plaintextBytes.size - off)
                        System.arraycopy(plaintextBytes, off, buf, 0, n)
                        litOut.write(buf, 0, n)
                        sigGen.update(buf, 0, n)
                        off += n
                    }
                }

                sigGen.generate().encode(pgpOut)
            }
            signedOut.toByteArray()
        }

        // Clear plaintext ASAP
        plaintextBytes.fill(0)

        // 2) Encrypt
        val encOut = ByteArrayOutputStream()
        val encGen = PGPEncryptedDataGenerator(
            JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(secureRandom())
                .setProvider(bc)
        )
        encGen.addMethod(
            JcePublicKeyKeyEncryptionMethodGenerator(recipientPublicKey.key)
                .setProvider(bc)
                .setSecureRandom(secureRandom())
        )

        // Also encrypt the session key for the sender so local device can decrypt OUT messages.
        if (senderPublicKey.key.keyID != recipientPublicKey.key.keyID) {
            encGen.addMethod(
                JcePublicKeyKeyEncryptionMethodGenerator(senderPublicKey.key)
                    .setProvider(bc)
                    .setSecureRandom(secureRandom())
            )
        }


        encGen.open(encOut, signedBytes.size.toLong()).use { cOut ->
            cOut.write(signedBytes)
        }

        // Clear signed material
        signedBytes.fill(0)

        return encOut.toByteArray()
    }
}
