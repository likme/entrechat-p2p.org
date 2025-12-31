/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.options

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.entrechat.app.EntrechatServiceManager
import com.entrechat.app.SettingsPrefs
import com.entrechat.app.databinding.ActivityOptionsBinding
import com.entrechat.app.tor.TorForegroundService
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class OptionsActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "OptionsActivity"
    }

    private lateinit var binding: ActivityOptionsBinding

    private var serviceStateJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityOptionsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupToolbar()
        setupKeepTorBackgroundSwitch()
        setupReconnectButton()
        setupTorButtons()
        renderStaticAbout()
    }

    private fun setupTorButtons() {
        binding.buttonRestartTorClean.setOnClickListener {
            EntrechatServiceManager.restartTorClean(applicationContext, reason = "options_restart_clean")
        }

        binding.buttonKillTorClearOnion.setOnClickListener {
            EntrechatServiceManager.killTorAndClearOnion(applicationContext, reason = "options_kill_clear_onion")
        }
    }


    override fun onStart() {
        super.onStart()
        startObservingServiceState()
    }

    override fun onStop() {
        super.onStop()
        serviceStateJob?.cancel()
        serviceStateJob = null
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener { finish() }
    }

    private fun setupKeepTorBackgroundSwitch() {
        val appCtx = applicationContext

        binding.switchKeepTorBackground.isChecked = SettingsPrefs.keepTorInBackground(appCtx)

        binding.switchKeepTorBackground.setOnCheckedChangeListener { _, isChecked ->
            SettingsPrefs.setKeepTorInBackground(appCtx, isChecked)

            if (isChecked) {
                // Persist Tor via foreground service and ensure runtime is running.
                TorForegroundService.start(appCtx)
                EntrechatServiceManager.start(appCtx)
            } else {
                // Stop foreground persistence. Do NOT force-stop Tor here.
                // Runtime lifecycle is owned by EntrechatServiceManager + OS.
                TorForegroundService.stop(appCtx)
            }

            Log.i(TAG, "keepTorInBackground=$isChecked")
        }
    }

    private fun setupReconnectButton() {
        val appCtx = applicationContext
        binding.buttonReconnectTor.setOnClickListener {
            EntrechatServiceManager.restart(appCtx, reason = "options_reconnect")
        }
    }

    private fun startObservingServiceState() {
        if (serviceStateJob?.isActive == true) return

        serviceStateJob = lifecycleScope.launch {
            EntrechatServiceManager.stateFlow.collect { st ->
                Log.i(TAG, "ServiceState UI = ${st::class.java.simpleName} st=$st")

                val stateText = when (st) {
                    is EntrechatServiceManager.AppState.INIT ->
                        "Stopped"

                    is EntrechatServiceManager.AppState.TOR_STARTING -> {
                        val d = st.detail?.trim().takeUnless { it.isNullOrBlank() }
                        if (d != null) "Starting ($d)..." else "Starting..."
                    }

                    is EntrechatServiceManager.AppState.TOR_READY ->
                        "Ready"

                    is EntrechatServiceManager.AppState.ERROR ->
                        "Error: ${st.code}"
                }

                val detailsText = when (st) {
                    is EntrechatServiceManager.AppState.TOR_READY -> {
                        val r = st.runtime
                        """
                        onion: ${r.onion}
                        local port: ${r.localPort}
                        socks: ${r.socksHost}:${r.socksPort}
                        """.trimIndent()
                    }

                    is EntrechatServiceManager.AppState.ERROR -> {
                        st.detail?.trim().orEmpty()
                    }

                    else -> ""
                }

                // These IDs must exist in activity_options.xml (txtRuntimeState, txtRuntimeDetails).
                binding.txtRuntimeState.text = stateText
                binding.txtRuntimeDetails.text = detailsText
            }
        }
    }

    private fun renderStaticAbout() {
        // Keep minimal. If you already set build/version elsewhere, keep it.
        // This assumes txtAboutValue exists (it does in your layout).
        val pkg = packageManager.getPackageInfo(packageName, 0)
        val versionName = pkg.versionName ?: "?"
        binding.txtAboutValue.text = "Entrechat $versionName"
    }
}
