/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

import com.entrechat.app.network.CryptoResult

interface CryptoService {
    fun verifyAndDecryptEnvelope(
        senderFingerprint: String,
        recipientFingerprint: String,
        payloadBase64: String
    ): CryptoResult

    fun encryptAndSignEnvelope(
        senderFingerprint: String,
        recipientFingerprint: String,
        plaintextJsonUtf8: ByteArray
    ): CryptoResult

}
