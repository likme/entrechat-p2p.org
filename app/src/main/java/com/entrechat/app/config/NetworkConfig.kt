/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.config

import java.util.concurrent.TimeUnit

object NetworkConfig {

    // Local HTTP server (device)
    const val LOCAL_HOST: String = "127.0.0.1"

    /**
     * Runtime rule:
     * - Do NOT use a fixed local port in production.
     * - Local HTTP server must bind on port=0 (ephemeral) and expose the chosen port to the orchestrator.
     *
     * This constant is kept ONLY for legacy/debug tooling and must not be used by the boot sequence.
     */
    const val LEGACY_LOCAL_PORT_DEBUG_ONLY: Int = 8080

    // Onion service
    const val ONION_VIRTUAL_PORT: Int = 80

    // API base paths
    const val HEALTH_ENDPOINT: String = "/health"
    val HEALTH_PATH: String
        get() = ProtocolConfig.API_BASE_PATH + HEALTH_ENDPOINT

    const val MESSAGE_ENDPOINT: String = "/messages"
    val MESSAGE_PATH: String
        get() = ProtocolConfig.API_BASE_PATH + MESSAGE_ENDPOINT

    const val IDENTITY_ENDPOINT: String = "/identity"
    val IDENTITY_PATH: String
        get() = ProtocolConfig.API_BASE_PATH + IDENTITY_ENDPOINT

    /**
     * NOTE:
     * Contact export must be done from UI via IdentityManager/ServiceManager gating.
     * This endpoint is legacy/debug only and should not be relied on for product logic.
     */
    const val CONTACT_EXPORT_ENDPOINT: String = "/contact_export"
    val CONTACT_EXPORT_PATH: String
        get() = ProtocolConfig.API_BASE_PATH + CONTACT_EXPORT_ENDPOINT

    const val CONTACT_IMPORT_ENDPOINT: String = "/contact_import"
    val CONTACT_IMPORT_PATH: String
        get() = ProtocolConfig.API_BASE_PATH + CONTACT_IMPORT_ENDPOINT

    const val CONTACTS_ENDPOINT: String = "/contacts"
    val CONTACTS_PATH: String
        get() = ProtocolConfig.API_BASE_PATH + CONTACTS_ENDPOINT

    // Debug endpoints (should be hidden behind debuggable checks)
    const val MESSAGE_SEND_PATH: String = "/v1/message_send"
    const val MESSAGES_PATH: String = "/v1/messages"

    // Timeouts
    val CONNECT_TIMEOUT_MS: Long = TimeUnit.SECONDS.toMillis(30)
    val READ_TIMEOUT_MS: Long = TimeUnit.SECONDS.toMillis(30)
    val WRITE_TIMEOUT_MS: Long = TimeUnit.SECONDS.toMillis(30)
}
