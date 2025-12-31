/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.identity

import com.entrechat.app.crypto.BlobCrypto
import com.entrechat.app.crypto.PgpKeyGenBc
import com.entrechat.app.db.IdentityDao
import com.entrechat.app.db.IdentityEntity
import org.bouncycastle.openpgp.PGPException
import java.io.ByteArrayOutputStream

class IdentityManager(
    private val identityDao: IdentityDao,
    private val blobCrypto: BlobCrypto
) {

    fun ensureIdentity(): IdentityEntity {
        val existing = identityDao.getActive()
        if (existing != null) return existing

        val rings = PgpKeyGenBc.generateRsa3072(userId = "entrechat")
        val primaryPub = rings.publicRing.publicKey
            ?: throw PGPException("Missing primary public key")

        val fingerprint = PgpKeyGenBc.fingerprintHexUpper(primaryPub)

        val publicBytes = ByteArrayOutputStream().use { out ->
            rings.publicRing.encode(out)
            out.toByteArray()
        }

        val secretBytes = ByteArrayOutputStream().use { out ->
            rings.secretRing.encode(out)
            out.toByteArray()
        }

        val encryptedSecret = try {
            blobCrypto.encrypt(secretBytes)
        } finally {
            secretBytes.fill(0)
        }

        val entity = IdentityEntity(
            fingerprint = fingerprint,
            onion = "",
            publicKeyBytes = publicBytes,
            privateKeyBlobEncrypted = encryptedSecret,
            isActive = true
        )

        identityDao.deactivateAll()
        identityDao.upsert(entity)
        identityDao.setActive(fingerprint)

        return entity
    }

    /**
     * Persist onion v3 for the single active identity.
     *
     * HARD RULES:
     * - onion must be non-empty and valid v3 (.onion, 56 base32 chars).
     * - idempotent: if same onion already stored, do nothing and return current identity.
     */
    fun bindOnionV3(onionRaw: String): IdentityEntity {
        val onion = onionRaw.trim().lowercase()
        require(onion.isNotBlank()) { "ONION_EMPTY" }
        require(isValidOnionV3(onion)) { "ONION_INVALID" }

        val id = ensureIdentity()
        val current = id.onion.trim().lowercase()

        if (current == onion) return id

        val updated = id.copy(onion = onion)
        identityDao.upsert(updated)
        identityDao.setActive(updated.fingerprint)

        return updated
    }

    fun hasValidOnion(): Boolean {
        val id = identityDao.getActive() ?: return false
        val onion = id.onion.trim().lowercase()
        return onion.isNotBlank() && isValidOnionV3(onion)
    }

    private fun isValidOnionV3(onion: String): Boolean {
        if (!onion.endsWith(".onion")) return false
        val host = onion.removeSuffix(".onion")
        if (host.length != 56) return false
        for (c in host) {
            val ok = (c in 'a'..'z') || (c in '2'..'7')
            if (!ok) return false
        }
        return true
    }
}
