/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import com.entrechat.app.crypto.PgpPrivateKey
import com.entrechat.app.crypto.PgpPublicKey

interface PgpEngine {
    fun decryptAndVerify(
        encryptedBytes: ByteArray,
        senderPublicKeyRingBytes: ByteArray,
        recipientPrivateKey: PgpPrivateKey
    ): ByteArray

    fun encryptAndSign(
        plaintextBytes: ByteArray,
        recipientPublicKey: PgpPublicKey,
        senderPublicKey: PgpPublicKey,
        senderPrivateKey: PgpPrivateKey
    ): ByteArray
}

