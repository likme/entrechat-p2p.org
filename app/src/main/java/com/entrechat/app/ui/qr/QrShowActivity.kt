/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.qr

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.entrechat.app.AppGraph
import com.entrechat.app.R
import com.entrechat.app.config.ProtocolConfig
import com.entrechat.app.db.InviteEntity
import com.entrechat.app.ui.common.Ec2QrCodec
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.journeyapps.barcodescanner.BarcodeEncoder
import java.security.SecureRandom

class QrShowActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_TEXT = "text"
        const val EXTRA_TITLE = "title"
        private const val TAG = "QrShowActivity"
    }

    private lateinit var qrText: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_show)

        val title = intent.getStringExtra(EXTRA_TITLE).orEmpty()

        val txtTitle = findViewById<TextView>(R.id.txtTitle)
        val txtRaw = findViewById<TextView>(R.id.txtRaw)
        val btnCopy = findViewById<Button>(R.id.btnCopy)
        val imgQr = findViewById<ImageView>(R.id.imgQr)

        txtTitle.text = if (title.isNotBlank()) title else "Invite"

        val localPort = runCatching { AppGraph.localMessageServer.getBoundPortOrNull() }.getOrNull()
        if (localPort == null || localPort <= 0) {
            Toast.makeText(this, "Tor not ready", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        val token = newInviteToken()
        val nowMs = System.currentTimeMillis()
        val expiresAt = nowMs + ProtocolConfig.INVITE_TTL_MS

        try {
            runBlockingDb {
                AppGraph.inviteDao.insert(
                    InviteEntity(
                        token = token,
                        createdAtMs = nowMs,
                        expiresAtMs = expiresAt
                    )
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "invite insert failed", t)
            Toast.makeText(this, "Cannot create invite", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        val inviteOnion = try {
            runBlockingDb {
                AppGraph.torManager.ensureInviteHiddenService(
                    localPort = localPort,
                    virtualPort = com.entrechat.app.config.NetworkConfig.ONION_VIRTUAL_PORT
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "ensureInviteHiddenService failed", t)
            Toast.makeText(this, "Cannot publish invite onion", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        qrText = try {
            Ec2QrCodec.encode(inviteOnion = inviteOnion, token = token)
        } catch (t: Throwable) {
            Log.e(TAG, "ec2 encode failed", t)
            Toast.makeText(this, "Cannot generate QR", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        txtRaw.text = "len=${qrText.length}"

        btnCopy.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Entrechat invite", qrText))
            Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
        }

        try {
            val hints = mapOf(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
                EncodeHintType.MARGIN to 1
            )
            val encoder = BarcodeEncoder()
            val bmp = encoder.encodeBitmap(qrText, BarcodeFormat.QR_CODE, 1200, 1200, hints)
            imgQr.setImageBitmap(bmp)
        } catch (t: Throwable) {
            Log.e(TAG, "QR encode failed len=${qrText.length}", t)
            Toast.makeText(this, "QR encode failed", Toast.LENGTH_LONG).show()
        }
    }

    private fun newInviteToken(): String {
        val b = ByteArray(ProtocolConfig.INVITE_TOKEN_BYTES)
        SecureRandom().nextBytes(b)
        return Base64.encodeToString(b, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    private fun <T> runBlockingDb(block: suspend () -> T): T =
        kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) { block() }
}
