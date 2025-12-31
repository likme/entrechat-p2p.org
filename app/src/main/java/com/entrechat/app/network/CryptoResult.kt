/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import org.json.JSONObject

data class CryptoResult(
    val success: Boolean,
    val plaintextJson: JSONObject? = null,
    val errorCode: String = "CRYPTO_ERROR"
)
