/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.config

object LimitsConfig {

    // Message
    const val MAX_BODY_CHARS: Int = 500

    // Payload
    const val MAX_HTTP_PAYLOAD_BYTES: Int = 64 * 1024

    // Anti-replay
    const val MAX_NONCES_PER_CONTACT: Int = 10_000
    const val NONCE_RETENTION_DAYS: Int = 7

    // Nonce size hard limit (defense in depth)
    const val MAX_NONCE_CHARS: Int = 256
}
