/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.config

object TorConfig {

    // SOCKS proxy exposed by Tor
    const val SOCKS_HOST: String = "127.0.0.1"
    const val SOCKS_PORT: Int = 9050

    // Optional control port (dev only)
    const val CONTROL_HOST: String = "127.0.0.1"
    const val CONTROL_PORT: Int = 9051

    // Bootstrap
    const val BOOTSTRAP_TIMEOUT_MS: Long = 120_000L
    const val BOOTSTRAP_POLL_INTERVAL_MS: Long = 750L

    // Onion publish (descriptor upload)
    const val HS_PUBLISH_TIMEOUT_MS: Long = 120_000L
}
