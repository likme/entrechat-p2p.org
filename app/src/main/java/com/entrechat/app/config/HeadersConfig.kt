/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.config

object HeadersConfig {

    const val CONTENT_TYPE_JSON: String = "application/json"

    const val HEADER_CONTENT_TYPE: String = "Content-Type"
    const val HEADER_USER_AGENT: String = "User-Agent"

    val USER_AGENT: String
        get() = "Entrechat/${ProtocolConfig.VERSION} (Android)"
}
