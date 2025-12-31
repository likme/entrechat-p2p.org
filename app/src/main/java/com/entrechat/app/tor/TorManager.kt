/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.tor

import kotlinx.coroutines.flow.StateFlow

interface TorManager {

    data class HostPort(val host: String, val port: Int)

    val state: StateFlow<TorState>

    fun start()
    fun stop()

    suspend fun awaitReady(timeoutMs: Long): Boolean
    fun isReady(): Boolean
    fun getSocksEndpoint(): HostPort

    suspend fun ensureHiddenService(localPort: Int, virtualPort: Int): String
    suspend fun ensureInviteHiddenService(localPort: Int, virtualPort: Int): String
    suspend fun dropInviteHiddenService()

    fun resetTorOnly()
    fun resetTorOnlyAndRestart()

    fun reconnect()

    fun stopService()
    fun resetTorOnlyAndStop()

}
