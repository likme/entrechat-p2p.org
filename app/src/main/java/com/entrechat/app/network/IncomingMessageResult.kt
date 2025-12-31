/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import fi.iki.elonen.NanoHTTPD

sealed class IncomingMessageResult {

    data class Ok(val msgId: String) : IncomingMessageResult()

    data class Rejected(
        val httpCode: NanoHTTPD.Response.IStatus,
        val errorCode: String,
        val msgId: String? = null
    ) : IncomingMessageResult()
}
