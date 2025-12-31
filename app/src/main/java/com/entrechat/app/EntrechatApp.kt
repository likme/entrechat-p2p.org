/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app

import android.app.Application
import android.content.Context
import com.entrechat.app.tor.TorForegroundService
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider


class EntrechatApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // Ensure embedded BouncyCastle is used instead of Android's stub "BC".
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        AppGraph.init(this)

        val keepTor = SettingsPrefs.keepTorInBackground(this)

        if (keepTor) {
            TorForegroundService.start(this)
        } else {
            // Process-bound runtime. May stop when app is backgrounded or process is killed.
            EntrechatServiceManager.start(this)
        }
    }
}

/**
 * Centralized settings access to avoid key duplication across the codebase.
 */
object SettingsPrefs {
    private const val FILE = "settings"
    private const val KEY_KEEP_TOR_BACKGROUND = "keep_tor_background"

    fun keepTorInBackground(ctx: Context): Boolean {
        return ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getBoolean(KEY_KEEP_TOR_BACKGROUND, false)
    }

    fun setKeepTorInBackground(ctx: Context, enabled: Boolean) {
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_KEEP_TOR_BACKGROUND, enabled)
            .apply()
    }
}
