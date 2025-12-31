/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import com.entrechat.app.debug.RuntimeFile
import com.entrechat.app.tor.TorManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.min

object EntrechatServiceManager {

    private const val TAG = "EntrechatServiceManager"

    private const val LOCAL_SERVER_BIND_TIMEOUT_MS = 5_000

    private const val INVITE_CLEANUP_INTERVAL_MS = 60_000L

    sealed class AppState {
        data object INIT : AppState()
        data class TOR_STARTING(val detail: String? = null) : AppState()
        data class TOR_READY(val runtime: RuntimeContext) : AppState()
        data class ERROR(val code: String, val detail: String? = null) : AppState()
    }

    data class RuntimeContext(
        val onion: String,
        val localPort: Int,
        val socksHost: String,
        val socksPort: Int,
    )

    @Volatile private var started = false
    @Volatile private var state: AppState = AppState.INIT

    private val _stateFlow = MutableStateFlow<AppState>(AppState.INIT)
    val stateFlow: StateFlow<AppState> = _stateFlow.asStateFlow()

    @Volatile private var appCtxRef: Context? = null

    private var scope: CoroutineScope? = null
    private var watchdogJob: Job? = null
    private var inviteCleanupJob: Job? = null

    private val bootSeq = AtomicLong(0)
    @Volatile private var activeBootId: Long = 0

    fun getState(): AppState = state

    private fun isDebuggable(appCtx: Context): Boolean {
        val flags = appCtx.applicationInfo.flags
        return (flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    fun start(context: Context) {
        synchronized(this) {
            if (started) return
            started = true

            val appCtx = context.applicationContext
            appCtxRef = appCtx

            val job = SupervisorJob()
            val s = CoroutineScope(job + Dispatchers.IO)
            scope = s

            val bootId = bootSeq.incrementAndGet()
            activeBootId = bootId

            s.launch { boot(appCtx, bootId, isRecovery = false) }
        }
    }

    fun restart(context: Context, reason: String? = null) {
        val appCtx = context.applicationContext
        synchronized(this) {
            if (!started) {
                start(appCtx)
                return
            }

            val s = scope ?: return
            val bootId = bootSeq.incrementAndGet()
            activeBootId = bootId

            watchdogJob?.cancel()
            watchdogJob = null

            inviteCleanupJob?.cancel()
            inviteCleanupJob = null

            s.launch { boot(appCtx, bootId, isRecovery = true, reason = reason) }
        }
    }

    fun restartTorClean(context: Context, reason: String? = null) {
        val appCtx = context.applicationContext
        synchronized(this) {
            if (!started) {
                start(appCtx)
                return
            }

            val bootId = bootSeq.incrementAndGet()
            activeBootId = bootId

            watchdogJob?.cancel(); watchdogJob = null
            inviteCleanupJob?.cancel(); inviteCleanupJob = null

            scope?.launch {
                try {
                    setState(AppState.TOR_STARTING("tor_reconnect"))
                    AppGraph.outgoingSender.detachTorClient()
                    AppGraph.torManager.reconnect() // stopService + start, no wipe
                    boot(appCtx, bootId, isRecovery = true, reason = reason ?: "restart_tor_clean")
                } catch (t: Throwable) {
                    Log.e(TAG, "restartTorClean failed", t)
                    setState(AppState.ERROR("RESTART_FAILED", t.message))
                }
            }
        }
    }

    fun killTorAndClearOnion(context: Context, reason: String? = null) {
        val appCtx = context.applicationContext
        synchronized(this) {
            activeBootId = bootSeq.incrementAndGet()

            watchdogJob?.cancel(); watchdogJob = null
            inviteCleanupJob?.cancel(); inviteCleanupJob = null

            runCatching { AppGraph.outgoingSender.detachTorClient() }
            runCatching { AppGraph.localMessageServer.stop() }

            // Wipe Tor state + stop TorService
            runCatching { AppGraph.torManager.resetTorOnlyAndStop() }

            // Clear onion from identity (minimal: bind empty)
            runCatching { AppGraph.identityManager.bindOnionV3("") }

            setState(AppState.INIT)
            Log.i(TAG, "killTorAndClearOnion done reason=${reason ?: "n/a"}")
        }
    }


    private suspend fun boot(appCtx: Context, bootId: Long, isRecovery: Boolean, reason: String? = null) {
        fun stillActive(): Boolean = started && activeBootId == bootId

        try {
            if (!stillActive()) return
            setState(AppState.TOR_STARTING(if (isRecovery) "rebuild" else "boot"))

            val runtime = buildRuntime(appCtx = appCtx, bootId = bootId, stillActive = ::stillActive, isRecovery = isRecovery)

            if (!stillActive()) return
            setState(AppState.TOR_READY(runtime))

            startWatchdog(appCtx)
            startInviteCleanup()

            val onionTag = runtime.onion.take(10) + "…"
            Log.i(TAG, "READY bootId=$bootId onion=$onionTag localPort=${runtime.localPort} socks=${runtime.socksHost}:${runtime.socksPort} recovery=$isRecovery reason=${reason ?: "n/a"}")
        } catch (ce: CancellationException) {
            Log.i(TAG, "boot cancelled bootId=$bootId")
        } catch (t: Throwable) {
            Log.e(TAG, "boot failed bootId=$bootId", t)

            if (started && activeBootId == bootId) {
                setState(AppState.ERROR(code = "BOOT_FAILED", detail = t.message))
            }

            val keepLocalServer = isDebuggable(appCtx)
            stopInternal(stopLocalServer = !keepLocalServer)
        }
    }

    private suspend fun buildRuntime(
        appCtx: Context,
        bootId: Long,
        stillActive: () -> Boolean,
        isRecovery: Boolean
    ): RuntimeContext {
        if (!stillActive()) throw CancellationException("inactive")

        setState(AppState.TOR_STARTING("identity"))
        AppGraph.identityManager.ensureIdentity()

        if (!stillActive()) throw CancellationException("inactive")

        val torManager = AppGraph.torManager

        if (isRecovery) {
            setState(AppState.TOR_STARTING("detach_sender"))
            runCatching { AppGraph.outgoingSender.detachTorClient() }

            setState(AppState.TOR_STARTING("tor_reset"))
            runCatching { torManager.resetTorOnlyAndRestart() }
                .getOrElse {
                    runCatching { torManager.stop() }
                    torManager.start()
                }
        } else {
            setState(AppState.TOR_STARTING("tor_start"))
            torManager.start()
        }

        if (!stillActive()) throw CancellationException("inactive")

        setState(AppState.TOR_STARTING("tor_bootstrap"))
        val ok = torManager.awaitReady(180_000)
        if (!ok) throw IllegalStateException("Tor bootstrap timeout")

        if (!stillActive()) throw CancellationException("inactive")

        val socks: TorManager.HostPort = torManager.getSocksEndpoint()

        if (!stillActive()) throw CancellationException("inactive")

        setState(AppState.TOR_STARTING("local_server_start"))
        val localPort = AppGraph.localMessageServer.startAndGetBoundPort(
            timeoutMs = LOCAL_SERVER_BIND_TIMEOUT_MS,
            daemon = false
        )

        if (!stillActive()) throw CancellationException("inactive")

        setState(AppState.TOR_STARTING("onion_publish"))
        val onion = torManager.ensureHiddenService(
            localPort = localPort,
            virtualPort = com.entrechat.app.config.NetworkConfig.ONION_VIRTUAL_PORT
        ).trim()

        if (onion.isBlank()) throw IllegalStateException("onion empty")
        if (!onion.endsWith(".onion")) throw IllegalStateException("onion malformed")

        if (!stillActive()) throw CancellationException("inactive")

        setState(AppState.TOR_STARTING("identity_bind_onion"))
        AppGraph.identityManager.bindOnionV3(onion)

        if (!stillActive()) throw CancellationException("inactive")

        setState(AppState.TOR_STARTING("arm_tor_client"))
        val torRemoteClient = AppGraph.buildTorRemoteClient(socks)
        AppGraph.outgoingSender.attachTorClient(torRemoteClient)

        return RuntimeContext(
            onion = onion,
            localPort = localPort,
            socksHost = socks.host,
            socksPort = socks.port
        )
    }

    private fun startWatchdog(appCtx: Context) {
        val s = scope ?: return
        watchdogJob?.cancel()

        watchdogJob = s.launch {
            var backoffMs = 2_000L
            while (isActive && started) {
                delay(backoffMs)

                val isOk = runCatching { isTorReadyNow() }.getOrDefault(false)
                if (isOk) {
                    backoffMs = 2_000L
                    continue
                }

                setState(AppState.TOR_STARTING("watchdog_recover"))
                runCatching {
                    restart(appCtx, reason = "watchdog_not_ready")
                }

                backoffMs = min(30_000L, backoffMs * 2)
            }
        }
    }

    private fun startInviteCleanup() {
        val s = scope ?: return
        inviteCleanupJob?.cancel()

        inviteCleanupJob = s.launch {
            while (isActive && started) {
                delay(INVITE_CLEANUP_INTERVAL_MS)

                val inviteDao = runCatching { AppGraph.db.inviteDao() }.getOrNull() ?: continue
                val nowMs = System.currentTimeMillis()

                runCatching {
                    inviteDao.purgeDead(nowMs)
                    val active = inviteDao.countActive(nowMs)
                    if (active == 0) {
                        AppGraph.torManager.dropInviteHiddenService()
                    }
                }
            }
        }
    }

    private fun isTorReadyNow(): Boolean {
        val tm = AppGraph.torManager

        val direct = runCatching {
            val m = tm::class.java.methods.firstOrNull { it.name == "isReady" && it.parameterTypes.isEmpty() }
            if (m != null) {
                (m.invoke(tm) as? Boolean) == true
            } else {
                runCatching { tm.getSocksEndpoint() }.isSuccess
            }
        }.getOrDefault(false)

        return direct
    }

    fun stop() {
        synchronized(this) {
            if (!started) return

            activeBootId = bootSeq.incrementAndGet()

            started = false
            setState(AppState.INIT)

            watchdogJob?.cancel()
            watchdogJob = null

            inviteCleanupJob?.cancel()
            inviteCleanupJob = null

            stopInternal(stopLocalServer = true)

            appCtxRef = null
            Log.i(TAG, "stopped")
        }
    }

    private fun stopInternal(stopLocalServer: Boolean = true) {
        runCatching { AppGraph.outgoingSender.detachTorClient() }
        if (stopLocalServer) {
            runCatching { AppGraph.localMessageServer.stop() }
        }
        runCatching { AppGraph.torManager.stop() }
        runCatching { scope?.cancel() }
        scope = null
    }

    private fun setState(newState: AppState) {
        state = newState
        _stateFlow.value = newState

        val appCtx = appCtxRef ?: return

        runCatching {
            when (newState) {
                is AppState.INIT -> {
                    RuntimeFile.delete(appCtx)
                }

                is AppState.TOR_STARTING -> {
                    val lp = runCatching { AppGraph.localMessageServer.getBoundPortOrNull() }.getOrNull()
                    RuntimeFile.write(
                        appCtx = appCtx,
                        state = "TOR_STARTING",
                        onion = null,
                        localPort = lp,
                        socksHost = null,
                        socksPort = null
                    )
                }

                is AppState.TOR_READY -> {
                    RuntimeFile.write(
                        appCtx = appCtx,
                        state = "READY",
                        onion = newState.runtime.onion,
                        localPort = newState.runtime.localPort,
                        socksHost = newState.runtime.socksHost,
                        socksPort = newState.runtime.socksPort
                    )
                }

                is AppState.ERROR -> {
                    val lp = runCatching { AppGraph.localMessageServer.getBoundPortOrNull() }.getOrNull()
                    RuntimeFile.write(
                        appCtx = appCtx,
                        state = "ERROR",
                        onion = null,
                        localPort = lp,
                        socksHost = null,
                        socksPort = null,
                        errorCode = newState.code,
                        errorDetail = newState.detail
                    )
                }
            }
        }
    }
}
