/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.tor

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import net.freehaven.tor.control.RawEventListener
import net.freehaven.tor.control.TorControlConnection
import org.torproject.jni.TorService
import java.io.File
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class TorManagerImpl(
    private val appContext: Context
) : TorManager {

    companion object {
        private const val TAG = "TorManager"

        private const val DEFAULT_HOST = "127.0.0.1"
        private const val DEFAULT_SOCKS_PORT = 9050

        private val TOR_EVENTS = listOf(
            "STATUS_CLIENT",
            "NOTICE",
            "WARN",
            "ERR",
            "CIRC",
            "HS_DESC"
        )

        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val HS_KEY_ALIAS = "entrechat_tor_hs_key_v1"
        private const val HS_KEY_FILE_NAME = "tor_hs_ed25519_v3.key.enc"
        private const val HS_KEY_FILE_PREFIX = "v1:"
        private const val GCM_TAG_BITS = 128
        private const val GCM_IV_BYTES = 12

        private const val PREFS_NAME = "entrechat_tor"
        private const val PREF_LAST_ONION = "last_onion"

        private const val DEBUG_EVENTS = false
    }

    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val hsPublishTimeoutMs: Long = com.entrechat.app.config.TorConfig.HS_PUBLISH_TIMEOUT_MS

    @Volatile private var torService: TorService? = null
    @Volatile private var authed = false

    private val hsKeyFile: File = appContext.getFileStreamPath(HS_KEY_FILE_NAME)

    private val torBootstrapped = AtomicBoolean(false)
    private val hsPublished = AtomicBoolean(false)
    private val ready = AtomicBoolean(false)

    private val currentOnion = AtomicReference<String?>(null)
    private val currentOnionPrivKey = AtomicReference<String?>(null)

    private val inviteOnion = AtomicReference<String?>(null)
    private val inviteServiceIdRef = AtomicReference<String?>(null)
    private val invitePublishWaiter = AtomicReference<CompletableDeferred<Unit>?>(null)

    private val eventsInstalled = AtomicBoolean(false)
    private val hsPublishWaiter = AtomicReference<CompletableDeferred<Unit>?>(null)
    private val hsServiceIdRef = AtomicReference<String?>(null)

    private val didAutoReset = AtomicBoolean(false)

    private val _state: MutableStateFlow<TorState> =
        MutableStateFlow(TorState.Stopped(onionHint = loadOnionHint()))
    override val state: StateFlow<TorState> = _state.asStateFlow()

    private val rawListener = RawEventListener { type, line ->
        if (type == "HS_DESC" && line != null) {
            val primarySid = hsServiceIdRef.get()
            val primaryWaiter = hsPublishWaiter.get()
            if (primarySid != null && primaryWaiter != null && !primaryWaiter.isCompleted && hsDescUploadedFor(primarySid, line)) {
                primaryWaiter.complete(Unit)
            }

            val invSid = inviteServiceIdRef.get()
            val invWaiter = invitePublishWaiter.get()
            if (invSid != null && invWaiter != null && !invWaiter.isCompleted && hsDescUploadedFor(invSid, line)) {
                invWaiter.complete(Unit)
            }
        }

        if (DEBUG_EVENTS && type != null && line != null) {
            Log.i(TAG, "TOR_EVENT $type $line")
        }
    }

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            Log.i(TAG, "TorService connected: $name")
            torService = (binder as TorService.LocalBinder).service
            resetState()
            _state.value = TorState.Starting(onionHint = loadOnionHint())
        }

        override fun onServiceDisconnected(name: ComponentName) {
            Log.w(TAG, "TorService disconnected: $name")
            torService = null
            resetState()
            _state.value = TorState.Error(
                code = TorState.ErrorCode.CONTROL_UNAVAILABLE,
                detail = "Tor service disconnected",
                recoverable = true,
                onionHint = loadOnionHint()
            )
        }
    }

    override fun start() {
        Log.i(TAG, "start()")
        resetState()
        _state.value = TorState.Starting(onionHint = loadOnionHint())

        val intent = Intent(appContext, TorService::class.java)
        try {
            appContext.startService(intent)
            appContext.bindService(intent, conn, Context.BIND_AUTO_CREATE)
        } catch (t: Throwable) {
            Log.e(TAG, "start/bind TorService failed", t)
            _state.value = TorState.Error(
                code = TorState.ErrorCode.UNKNOWN,
                detail = "Tor start failed: ${t.message}",
                recoverable = true,
                onionHint = loadOnionHint()
            )
        }
    }

    override fun stop() {
        Log.i(TAG, "stop()")
        runCatching { appContext.unbindService(conn) }.onFailure { /* ignore */ }
        torService = null
        resetState()
        _state.value = TorState.Stopped(onionHint = loadOnionHint())
    }

    override fun reconnect() {
        Log.i(TAG, "reconnect()")

        // Detach from current service instance.
        runCatching { appContext.unbindService(conn) }.onFailure { /* ignore */ }
        torService = null
        resetState()

        // Stop then start to force a clean service lifecycle.
        runCatching { appContext.stopService(Intent(appContext, TorService::class.java)) }
            .onFailure { /* ignore */ }

        start()
    }

    override fun stopService() {
        Log.i(TAG, "stopService()")
        runCatching { appContext.unbindService(conn) }.onFailure { /* ignore */ }
        torService = null

        runCatching { appContext.stopService(Intent(appContext, TorService::class.java)) }
            .onFailure { /* ignore */ }

        resetState()
        _state.value = TorState.Stopped(onionHint = loadOnionHint())
    }

    override fun resetTorOnlyAndStop() {
        Log.w(TAG, "resetTorOnlyAndStop()")
        resetTorOnly() // deletes HS key + tor dirs + PREF_LAST_ONION, sets state Stopped(onionHint=null)
        runCatching { appContext.stopService(Intent(appContext, TorService::class.java)) }
            .onFailure { /* ignore */ }
    }


    override suspend fun awaitReady(timeoutMs: Long): Boolean =
        withContext(Dispatchers.IO) {
            val start = System.currentTimeMillis()
            var lastProgress = -1

            while (System.currentTimeMillis() - start < timeoutMs) {
                val cc = getControlOrNull()
                if (cc != null) {
                    ensureEventsInstalled(cc)

                    val bp = runCatching { cc.getInfo("status/bootstrap-phase") }
                        .getOrNull()
                        .orEmpty()

                    val bi = parseBootstrapPhase(bp)
                    if (bi != null && bi.progress in 0..99 && bi.progress != lastProgress) {
                        lastProgress = bi.progress
                        _state.value = TorState.Bootstrapping(
                            progress = bi.progress,
                            tag = bi.tag,
                            summary = bi.summary,
                            onionHint = loadOnionHint()
                        )
                    }

                    if (bp.contains("PROGRESS=100") && bp.contains("TAG=done")) {
                        torBootstrapped.set(true)
                        refreshReady()

                        val socksPort = getTorServicePort("getSocksPort", DEFAULT_SOCKS_PORT)
                        val hint = loadOnionHint()

                        // If HS is already published (rare but possible), be explicit.
                        _state.value = TorState.TorReady(
                            socksHost = DEFAULT_HOST,
                            socksPort = socksPort,
                            onionHint = hint
                        )
                        Log.i(TAG, "Tor bootstrap done")
                        return@withContext true
                    }
                } else {
                    // Not an error: service may not be ready yet.
                    if (_state.value !is TorState.Starting) {
                        _state.value = TorState.Starting(onionHint = loadOnionHint())
                    }
                }

                delay(com.entrechat.app.config.TorConfig.BOOTSTRAP_POLL_INTERVAL_MS)
            }

            Log.e(TAG, "awaitReady timeout")

            _state.value = TorState.Error(
                code = TorState.ErrorCode.BOOTSTRAP_TIMEOUT,
                detail = "Tor bootstrap timeout",
                recoverable = true,
                onionHint = loadOnionHint()
            )

            if (didAutoReset.compareAndSet(false, true)) {
                Log.w(TAG, "bootstrap timeout, auto reset tor-only then restart once")
                resetTorOnlyAndRestart()
            }

            false
        }

    override fun isReady(): Boolean = ready.get()

    override fun getSocksEndpoint(): TorManager.HostPort {
        val p = getTorServicePort("getSocksPort", DEFAULT_SOCKS_PORT)
        return TorManager.HostPort(DEFAULT_HOST, p)
    }

    override suspend fun ensureHiddenService(localPort: Int, virtualPort: Int): String =
        withContext(Dispatchers.IO) {
            require(localPort in 1..65535) { "bad localPort=$localPort" }
            require(virtualPort in 1..65535) { "bad virtualPort=$virtualPort" }

            val ok = awaitReady(com.entrechat.app.config.TorConfig.BOOTSTRAP_TIMEOUT_MS)
            if (!ok) {
                _state.value = TorState.Error(
                    code = TorState.ErrorCode.BOOTSTRAP_TIMEOUT,
                    detail = "Tor not bootstrapped",
                    recoverable = true,
                    onionHint = loadOnionHint()
                )
                throw IllegalStateException("Tor not bootstrapped")
            }

            val cc = getControlOrThrow()
            ensureEventsInstalled(cc)

            val target = "$DEFAULT_HOST:$localPort"
            val ports: Map<Int, String> = mapOf(virtualPort to target)

            val privKey: String? = readEncryptedHiddenServiceKey()

            val reply: Map<String, String> =
                if (!privKey.isNullOrBlank()) {
                    cc.addOnion("ED25519-V3:$privKey", ports)
                } else {
                    val r = cc.addOnion("NEW:ED25519-V3", ports)
                    r["onionPrivKey"]?.let { writeEncryptedHiddenServiceKey(it) }
                    r
                }

            val onionAddress = reply["onionAddress"]?.trim().orEmpty()
            if (onionAddress.isBlank()) {
                _state.value = TorState.Error(
                    code = TorState.ErrorCode.UNKNOWN,
                    detail = "ADD_ONION returned no onionAddress",
                    recoverable = true,
                    onionHint = loadOnionHint()
                )
                throw IllegalStateException("ADD_ONION returned no onionAddress. Reply keys=${reply.keys}")
            }

            val onion = if (onionAddress.endsWith(".onion")) onionAddress else "$onionAddress.onion"
            val sid = onion.removeSuffix(".onion").trim()
            if (sid.isBlank()) {
                _state.value = TorState.Error(
                    code = TorState.ErrorCode.UNKNOWN,
                    detail = "Invalid onionAddress",
                    recoverable = true,
                    onionHint = loadOnionHint()
                )
                throw IllegalStateException("Invalid serviceId from onionAddress=$onion")
            }

            currentOnion.set(onion)
            currentOnionPrivKey.set(reply["onionPrivKey"]?.trim())
            persistOnionHint(onion)

            hsPublished.set(false)
            refreshReady()

            val socksPort = getTorServicePort("getSocksPort", DEFAULT_SOCKS_PORT)

            _state.value = TorState.HiddenServicePublishing(
                onion = onion,
                socksHost = DEFAULT_HOST,
                socksPort = socksPort,
                onionHint = onion
            )

            val published = CompletableDeferred<Unit>()
            hsServiceIdRef.set(sid)
            hsPublishWaiter.set(published)

            try {
                withTimeout(hsPublishTimeoutMs) { published.await() }
            } catch (t: Throwable) {
                hsPublishWaiter.set(null)
                hsServiceIdRef.set(null)
                hsPublished.set(false)
                refreshReady()

                val code = if (t is TimeoutCancellationException) {
                    TorState.ErrorCode.HS_PUBLISH_TIMEOUT
                } else {
                    TorState.ErrorCode.UNKNOWN
                }

                _state.value = TorState.Error(
                    code = code,
                    detail = "Hidden service publish failed",
                    recoverable = true,
                    onionHint = loadOnionHint()
                )

                throw IllegalStateException(
                    "Hidden service descriptor not uploaded within ${hsPublishTimeoutMs}ms sid=${sid.take(12)}",
                    t
                )
            }

            hsPublishWaiter.set(null)
            hsServiceIdRef.set(null)
            hsPublished.set(true)
            refreshReady()

            _state.value = TorState.Ready(
                onion = onion,
                socksHost = DEFAULT_HOST,
                socksPort = getTorServicePort("getSocksPort", DEFAULT_SOCKS_PORT),
                onionHint = onion
            )

            Log.i(TAG, "Onion ready: $onion -> $virtualPort $target")
            onion
        }

    override suspend fun ensureInviteHiddenService(localPort: Int, virtualPort: Int): String =
        withContext(Dispatchers.IO) {
            inviteOnion.get()?.let { return@withContext it }

            require(localPort in 1..65535) { "bad localPort=$localPort" }
            require(virtualPort in 1..65535) { "bad virtualPort=$virtualPort" }

            if (!awaitReady(com.entrechat.app.config.TorConfig.BOOTSTRAP_TIMEOUT_MS)) {
                throw IllegalStateException("Tor not bootstrapped")
            }

            val cc = getControlOrThrow()
            ensureEventsInstalled(cc)

            val target = "$DEFAULT_HOST:$localPort"
            val ports: Map<Int, String> = mapOf(virtualPort to target)

            val reply: Map<String, String> = cc.addOnion("NEW:ED25519-V3", ports)

            val onionAddress = reply["onionAddress"]?.trim().orEmpty()
            if (onionAddress.isBlank()) {
                throw IllegalStateException("ADD_ONION(invite) returned no onionAddress. Reply keys=${reply.keys}")
            }

            val onion = if (onionAddress.endsWith(".onion")) onionAddress else "$onionAddress.onion"
            val sid = onion.removeSuffix(".onion").trim()
            if (sid.isBlank()) throw IllegalStateException("Invalid invite serviceId from onionAddress=$onion")

            val published = CompletableDeferred<Unit>()
            inviteServiceIdRef.set(sid)
            invitePublishWaiter.set(published)

            try {
                withTimeout(hsPublishTimeoutMs) { published.await() }
            } catch (t: Throwable) {
                invitePublishWaiter.set(null)
                inviteServiceIdRef.set(null)
                inviteOnion.set(null)

                val code = if (t is TimeoutCancellationException) {
                    TorState.ErrorCode.HS_PUBLISH_TIMEOUT
                } else {
                    TorState.ErrorCode.UNKNOWN
                }

                _state.value = TorState.Error(
                    code = code,
                    detail = "Invite hidden service publish failed",
                    recoverable = true,
                    onionHint = loadOnionHint()
                )

                throw IllegalStateException(
                    "Invite descriptor not uploaded within ${hsPublishTimeoutMs}ms sid=${sid.take(12)}",
                    t
                )
            } finally {
                invitePublishWaiter.set(null)
            }

            inviteOnion.set(onion)
            Log.i(TAG, "Invite onion ready: $onion -> $virtualPort $target")
            onion
        }

    override suspend fun dropInviteHiddenService() {
        withContext(Dispatchers.IO) {
            val sid = inviteServiceIdRef.getAndSet(null) ?: run {
                inviteOnion.set(null)
                invitePublishWaiter.set(null)
                return@withContext
            }

            invitePublishWaiter.set(null)
            inviteOnion.set(null)

            val cc = getControlOrNull() ?: return@withContext

            runCatching {
                val m = cc.javaClass.methods.firstOrNull { it.name == "delOnion" && it.parameterTypes.size == 1 }
                if (m != null) {
                    m.invoke(cc, sid)
                } else {
                    val m2 = cc.javaClass.methods.firstOrNull { it.name == "sendCommand" && it.parameterTypes.size == 1 }
                    if (m2 != null) {
                        m2.invoke(cc, "DEL_ONION $sid")
                    } else {
                        throw IllegalStateException("No delOnion/sendCommand available on TorControlConnection")
                    }
                }
            }.onFailure {
                Log.w(TAG, "DEL_ONION failed: ${it.message}")
            }
        }
    }

    override fun resetTorOnly() {
        Log.w(TAG, "resetTorOnly()")

        runCatching { appContext.unbindService(conn) }
        torService = null
        resetState()

        runCatching { if (hsKeyFile.exists()) hsKeyFile.delete() }
            .onFailure { Log.e(TAG, "Failed to delete hs key file: ${it.message}") }

        deleteDirIfExists(File(appContext.filesDir, "tor"))
        deleteDirIfExists(File(appContext.noBackupFilesDir, "tor"))
        deleteDirIfExists(File(appContext.filesDir, "tordata"))
        deleteDirIfExists(File(appContext.noBackupFilesDir, "tordata"))

        // Reset implies the onion is no longer valid (HS key removed).
        prefs.edit().remove(PREF_LAST_ONION).apply()

        _state.value = TorState.Stopped(onionHint = null)
    }

    override fun resetTorOnlyAndRestart() {
        resetTorOnly()
        start()
    }

    private fun resetState() {
        authed = false
        torBootstrapped.set(false)
        hsPublished.set(false)
        ready.set(false)

        currentOnion.set(null)
        currentOnionPrivKey.set(null)

        inviteOnion.set(null)
        inviteServiceIdRef.set(null)
        invitePublishWaiter.set(null)

        eventsInstalled.set(false)
        hsPublishWaiter.set(null)
        hsServiceIdRef.set(null)
        didAutoReset.set(false)
    }

    private fun refreshReady() {
        ready.set(torBootstrapped.get() && hsPublished.get())
    }

    private fun getTorServicePort(methodName: String, fallback: Int): Int {
        val svc = torService ?: return fallback
        return try {
            val m = svc.javaClass.methods.firstOrNull { it.name == methodName && it.parameterTypes.isEmpty() }
                ?: return fallback
            (m.invoke(svc) as? Int) ?: fallback
        } catch (_: Throwable) {
            fallback
        }
    }

    private suspend fun getControlOrNull(): TorControlConnection? =
        withContext(Dispatchers.IO) {
            val svc = torService ?: return@withContext null
            val cc = svc.torControlConnection ?: return@withContext null

            if (!authed) {
                runCatching { cc.authenticate(byteArrayOf()) }
                    .onSuccess { authed = true }
                    .onFailure {
                        Log.e(TAG, "Tor control authentication failed: ${it.message}")
                        _state.value = TorState.Error(
                            code = TorState.ErrorCode.CONTROL_UNAVAILABLE,
                            detail = "Tor control auth failed",
                            recoverable = true,
                            onionHint = loadOnionHint()
                        )
                    }
            }

            if (authed) cc else null
        }

    private suspend fun getControlOrThrow(): TorControlConnection =
        getControlOrNull() ?: throw IllegalStateException("TorControlConnection unavailable (Tor not ready)")

    private fun ensureEventsInstalled(cc: TorControlConnection) {
        if (eventsInstalled.get()) return

        runCatching { cc.setEvents(TOR_EVENTS) }
            .onFailure { Log.e(TAG, "setEvents failed: ${it.message}") }

        if (eventsInstalled.compareAndSet(false, true)) {
            runCatching { cc.addRawEventListener(rawListener) }
                .onFailure { Log.e(TAG, "addRawEventListener failed: ${it.message}") }
        }
    }


    private fun hsDescUploadedFor(serviceId: String, line: String): Boolean {
        val ok = line.contains("UPLOADED", true) || (line.contains("UPLOAD", true) && !line.contains("FAILED", true))
        return ok && line.contains(serviceId, true)
    }

    private data class BootstrapInfo(val progress: Int, val tag: String?, val summary: String?)

    private fun parseBootstrapPhase(s: String): BootstrapInfo? {
        // Example: "NOTICE BOOTSTRAP PROGRESS=80 TAG=ap_conn SUMMARY=\"Connecting to a relay\""
        val prog = Regex("""PROGRESS=(\d+)""").find(s)?.groupValues?.getOrNull(1)?.toIntOrNull() ?: return null
        val tag = Regex("""TAG=([^\s]+)""").find(s)?.groupValues?.getOrNull(1)
        val summary = Regex("""SUMMARY="?([^"]*)"?""").find(s)?.groupValues?.getOrNull(1)
        return BootstrapInfo(prog.coerceIn(0, 100), tag, summary)
    }

    private fun loadOnionHint(): String? =
        prefs.getString(PREF_LAST_ONION, null)?.trim()?.takeIf { it.isNotBlank() }

    private fun persistOnionHint(onion: String) {
        val v = onion.trim()
        if (v.isBlank()) return
        prefs.edit().putString(PREF_LAST_ONION, v).apply()
    }

    private fun deleteDirIfExists(dir: File) {
        if (!dir.exists()) return
        runCatching { dir.deleteRecursively() }
            .onFailure { Log.e(TAG, "Failed to delete ${dir.absolutePath}: ${it.message}") }
    }

    private fun readEncryptedHiddenServiceKey(): String? {
        if (!hsKeyFile.exists()) return null
        val text = runCatching { hsKeyFile.readText() }.getOrNull()?.trim().orEmpty()
        if (!text.startsWith(HS_KEY_FILE_PREFIX)) return null

        val b64 = text.removePrefix(HS_KEY_FILE_PREFIX)
        val bytes = runCatching { Base64.decode(b64, Base64.NO_WRAP) }.getOrNull() ?: return null
        if (bytes.size <= GCM_IV_BYTES) return null

        val iv = bytes.copyOfRange(0, GCM_IV_BYTES)
        val ct = bytes.copyOfRange(GCM_IV_BYTES, bytes.size)

        val pt = runCatching { aesGcmDecrypt(ct, iv) }.getOrNull() ?: return null
        val key = runCatching { String(pt, Charsets.UTF_8).trim() }.getOrNull()
        pt.fill(0)
        return key?.ifBlank { null }
    }

    private fun writeEncryptedHiddenServiceKey(privKey: String) {
        val trimmed = privKey.trim()
        require(trimmed.isNotEmpty()) { "HS_PRIVKEY_EMPTY" }

        val pt = trimmed.toByteArray(Charsets.UTF_8)

        val payload = runCatching {
            aesGcmEncryptWithIvPrefix(pt)
        }.getOrElse {
            pt.fill(0)
            throw IllegalStateException("HS_KEY_WRITE_ENCRYPT_FAILED:${it.message}", it)
        }

        pt.fill(0)

        val out = HS_KEY_FILE_PREFIX + Base64.encodeToString(payload, Base64.NO_WRAP)
        runCatching { hsKeyFile.writeText(out) }
            .onFailure { Log.e(TAG, "Failed to persist encrypted HS key: ${it.message}") }
    }

    private fun getAesGcmCipher(): Cipher {
        return runCatching {
            Cipher.getInstance("AES/GCM/NoPadding", "AndroidKeyStoreBCWorkaround")
        }.recoverCatching {
            Cipher.getInstance("AES/GCM/NoPadding", "AndroidKeyStore")
        }.getOrElse {
            Cipher.getInstance("AES/GCM/NoPadding")
        }
    }

    private fun isUsableAesGcmKey(key: SecretKey): Boolean {
        return runCatching {
            val cipher = getAesGcmCipher()
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val ct = cipher.doFinal(byteArrayOf(1, 2, 3))
            val iv = cipher.iv
            ct.isNotEmpty() && iv != null && iv.size == GCM_IV_BYTES
        }.getOrDefault(false)
    }

    private fun getOrCreateAesKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        val existing: SecretKey? = runCatching {
            ks.getKey(HS_KEY_ALIAS, null) as? SecretKey
        }.getOrNull()

        if (existing != null) {
            if (isUsableAesGcmKey(existing)) return existing

            Log.w(TAG, "Keystore AES key is unusable, deleting alias=$HS_KEY_ALIAS")
            runCatching { ks.deleteEntry(HS_KEY_ALIAS) }
        }

        val kg = KeyGenerator.getInstance("AES", KEYSTORE_PROVIDER)
        val spec = android.security.keystore.KeyGenParameterSpec.Builder(
            HS_KEY_ALIAS,
            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                android.security.keystore.KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        kg.init(spec)
        return kg.generateKey()
    }

    private fun aesGcmEncryptWithIvPrefix(plaintext: ByteArray): ByteArray {
        require(plaintext.isNotEmpty()) { "HS_KEY_PLAINTEXT_EMPTY" }

        val key = getOrCreateAesKey()
        val cipher = getAesGcmCipher()

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key)
        } catch (t: Throwable) {
            throw IllegalStateException(
                "HS_KEY_AESGCM_INIT_ENCRYPT_FAILED:${t.javaClass.simpleName}:${t.message}",
                t
            )
        }

        val ct = cipher.doFinal(plaintext)
        val iv = cipher.iv ?: throw IllegalStateException("HS_KEY_AESGCM_NO_IV_FROM_PROVIDER")

        if (iv.size != GCM_IV_BYTES) {
            throw IllegalStateException("HS_KEY_AESGCM_BAD_IV_LEN:${iv.size}")
        }

        return iv + ct
    }

    private fun aesGcmDecrypt(ciphertext: ByteArray, iv: ByteArray): ByteArray {
        require(ciphertext.isNotEmpty()) { "HS_KEY_CIPHERTEXT_EMPTY" }
        require(iv.size == GCM_IV_BYTES) { "HS_KEY_IV_BAD_LENGTH:${iv.size}" }

        val key = getOrCreateAesKey()
        val cipher = getAesGcmCipher()

        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        } catch (t: Throwable) {
            throw IllegalStateException(
                "HS_KEY_AESGCM_INIT_DECRYPT_FAILED:${t.javaClass.simpleName}:${t.message}",
                t
            )
        }

        return cipher.doFinal(ciphertext)
    }
}
