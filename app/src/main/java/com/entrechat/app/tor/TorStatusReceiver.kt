/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.tor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class TorStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "org.torproject.android.intent.action.STATUS") return

        val status = intent.getStringExtra("status")
            ?: intent.getStringExtra("STATUS")
            ?: "<no-status>"

        val extraKeys = intent.extras?.keySet()?.sorted()?.joinToString(",") ?: "<no-extras>"
        Log.i("TorStatus", "STATUS action received status=$status keys=$extraKeys")
    }
}
