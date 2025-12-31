/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

interface MessageRepository {

    fun storeIncomingMessage(
        msgId: String,
        convId: String,
        senderFp: String,
        recipientFp: String,
        createdAt: Long,
        ciphertextBase64: String
    )
}
