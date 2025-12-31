/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.tor

sealed class TorState {

    abstract val onionHint: String?

    data class Stopped(
        override val onionHint: String? = null
    ) : TorState()

    data class Starting(
        override val onionHint: String? = null
    ) : TorState()

    data class Bootstrapping(
        val progress: Int,
        val tag: String? = null,
        val summary: String? = null,
        override val onionHint: String? = null
    ) : TorState()

    data class TorReady(
        val socksHost: String,
        val socksPort: Int,
        override val onionHint: String? = null
    ) : TorState()

    data class HiddenServicePublishing(
        val onion: String,
        val socksHost: String,
        val socksPort: Int,
        override val onionHint: String? = onion
    ) : TorState()

    data class Ready(
        val onion: String,
        val socksHost: String,
        val socksPort: Int,
        override val onionHint: String? = onion
    ) : TorState()

    data class Error(
        val code: ErrorCode,
        val detail: String? = null,
        val recoverable: Boolean = true,
        override val onionHint: String? = null
    ) : TorState()

    enum class ErrorCode {
        BOOTSTRAP_TIMEOUT,
        HS_PUBLISH_TIMEOUT,
        CONTROL_UNAVAILABLE,
        IO,
        UNKNOWN
    }
}
