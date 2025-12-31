/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import fi.iki.elonen.NanoHTTPD

object HttpStatuses {

    val UNPROCESSABLE_ENTITY_422 = object : NanoHTTPD.Response.IStatus {
        override fun getRequestStatus() = 422
        override fun getDescription() = "422 Unprocessable Entity"
    }

    val REQUEST_ENTITY_TOO_LARGE_413 = object : NanoHTTPD.Response.IStatus {
        override fun getRequestStatus() = 413
        override fun getDescription() = "413 Payload Too Large"
    }

    val CONFLICT_409 = object : NanoHTTPD.Response.IStatus {
        override fun getRequestStatus() = 409
        override fun getDescription() = "409 Conflict"
    }

    val GONE_410 = object : NanoHTTPD.Response.IStatus {
        override fun getRequestStatus() = 410
        override fun getDescription() = "410 Gone"
    }
}
