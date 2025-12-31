/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

class PgpEncryptorBc {
    /**
     * Retourne un message PGP binaire (bytes).
     * - chiffre pour recipientPublicKey
     * - signe avec senderPrivateKey (si dispo)
     */
    fun encryptAndSign(
        plaintext: ByteArray,
        recipientPublicKeyBytes: ByteArray,
        senderPrivateKeyBytes: ByteArray,
        senderPrivateKeyPassphrase: CharArray? = null
    ): ByteArray {
        TODO("impl BC OpenPGP")
    }
}
