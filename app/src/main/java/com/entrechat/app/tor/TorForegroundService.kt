/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.tor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.entrechat.app.EntrechatServiceManager
import com.entrechat.app.MainActivity
import com.entrechat.app.R

/**
 * Foreground service responsible for keeping the Tor runtime alive when the app is backgrounded.
 *
 * Why this exists:
 * - On modern Android, background execution is heavily restricted.
 * - A long-lived network stack (Tor + hidden service + local server) is likely to be killed when the app
 *   moves to background unless it is hosted by a ForegroundService with a persistent notification.
 *
 * This service does not own application graph initialization. It only orchestrates start/stop of the
 * existing runtime through EntrechatServiceManager, which remains the single source of truth.
 */
class TorForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                EntrechatServiceManager.start(applicationContext)
            }
            ACTION_STOP -> {
                // Stop foreground first to remove persistence. Then stop runtime explicitly.
                stopForeground(STOP_FOREGROUND_REMOVE)
                EntrechatServiceManager.stop()
                stopSelf()
            }
            ACTION_RESTART -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                EntrechatServiceManager.restart(applicationContext, reason = "foreground_service_restart")
            }
            else -> {
                // Defensive default: keep foreground and ensure runtime.
                startForeground(NOTIFICATION_ID, buildNotification())
                EntrechatServiceManager.start(applicationContext)
            }
        }
        return START_STICKY
    }

    private fun buildNotification(): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openAppPi = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or immutableFlag()
        )

        val restartIntent = Intent(this, TorForegroundService::class.java).apply { action = ACTION_RESTART }
        val restartPi = PendingIntent.getService(
            this,
            1,
            restartIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or immutableFlag()
        )

        val stopIntent = Intent(this, TorForegroundService::class.java).apply { action = ACTION_STOP }
        val stopPi = PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or immutableFlag()
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_logo_entrechat)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(openAppPi)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, getString(R.string.action_reconnect_tor), restartPi)
            .addAction(0, getString(android.R.string.cancel), stopPi)
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val existing = nm.getNotificationChannel(CHANNEL_ID)
        if (existing != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            "Entrechat Tor",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps Tor running in background"
            setShowBadge(false)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        nm.createNotificationChannel(channel)
    }

    private fun immutableFlag(): Int {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
    }

    companion object {
        const val ACTION_START = "com.entrechat.app.tor.action.START"
        const val ACTION_STOP = "com.entrechat.app.tor.action.STOP"
        const val ACTION_RESTART = "com.entrechat.app.tor.action.RESTART"

        private const val CHANNEL_ID = "tor_foreground"
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            val i = Intent(context, TorForegroundService::class.java).apply { action = ACTION_START }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(i)
            } else {
                context.startService(i)
            }
        }

        fun stop(context: Context) {
            val i = Intent(context, TorForegroundService::class.java).apply { action = ACTION_STOP }
            context.startService(i)
        }

        fun restart(context: Context) {
            val i = Intent(context, TorForegroundService::class.java).apply { action = ACTION_RESTART }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(i)
            } else {
                context.startService(i)
            }
        }
    }
}
