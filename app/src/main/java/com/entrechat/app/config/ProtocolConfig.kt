/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.config

object ProtocolConfig {

    const val VERSION: Int = 1

    const val VERSION_INVITE_V2: Int = 2

    const val TYPE_MESSAGE: String = "msg"
    const val TYPE_ADDR_UPDATE: String = "addr_update"
    const val TYPE_CONTACT: String = "contact"
    const val TYPE_CONTACT_PART: String = "contact_part"
    const val TYPE_CONTACT_EXPORT: String = "contact_export"

    const val API_BASE_PATH: String = "/v1"

    const val INVITE_PATH_PREFIX: String = "/invite/"

    const val INVITE_TOKEN_BYTES: Int = 16

    const val INVITE_TTL_MS: Long = 10 * 60 * 1000L

    const val SAS_CONTEXT: String = "ec2-sas-v1"
}
