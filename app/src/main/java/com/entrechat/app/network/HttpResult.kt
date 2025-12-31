/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

data class HttpResult(
    val success: Boolean,
    val code: Int?,
    val body: String?,
    val error: Throwable? = null
)
