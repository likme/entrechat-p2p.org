/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.identity

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.entrechat.app.AppGraph
import com.entrechat.app.R
import com.entrechat.app.databinding.ActivityIdentityBinding
import com.entrechat.app.ui.common.FpFormat
import com.entrechat.app.ui.common.JsonContactCodec
import com.entrechat.app.ui.common.io
import com.entrechat.app.ui.qr.QrShowActivity
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class IdentityActivity : AppCompatActivity() {

    private lateinit var binding: ActivityIdentityBinding

    private var refreshJob: Job? = null

    private val openDoc = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) importFromUri(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityIdentityBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnRefresh.setOnClickListener {
            refreshJob?.cancel()
            refreshJob = null
            lifecycleScope.launch { refreshOnce() }
            startAutoRefresh()
        }


        binding.btnCopyFp.setOnClickListener { copyFingerprint() }
        binding.btnShareContact.setOnClickListener { shareMyContactJson() }
        binding.btnShowQr.setOnClickListener { showMyContactQr() }
        binding.btnImportContact.setOnClickListener { openDoc.launch(arrayOf("application/json", "text/*")) }

        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        startAutoRefresh()
    }

    override fun onStop() {
        super.onStop()
        refreshJob?.cancel()
        refreshJob = null
    }

    private fun startAutoRefresh() {
        if (refreshJob?.isActive == true) return

        refreshJob = lifecycleScope.launch {
            while (true) {
                val torReady = refreshOnce()
                // If Tor is ready, we can refresh less often.
                delay(if (torReady) 5_000L else 1_000L)
            }
        }
    }

    /**
     * @return true if Tor looks ready from current identity state (onion present).
     */
    private suspend fun refreshOnce(): Boolean {
        binding.txtStatus.text = getString(R.string.status_loading)

        val id = io { AppGraph.identityDao.getActive() }
        if (id == null) {
            binding.txtStatus.text = getString(R.string.status_identity_not_ready)
            binding.txtFingerprint.text = "—"
            binding.txtOnion.text = "—"
            return false
        }

        val fp = FpFormat.canonical(id.fingerprint)
        binding.txtStatus.text = getString(R.string.status_ready)
        binding.txtFingerprint.text = fp

        val onion = id.onion.trim()
        val torOk = onion.isNotBlank()
        binding.txtOnion.text = if (torOk) onion else getString(R.string.tor_not_running)

        return torOk
    }

    private fun copyFingerprint() {
        val fp = binding.txtFingerprint.text?.toString().orEmpty()
        if (fp.isBlank() || fp == "—") return

        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("Entrechat fingerprint", fp))
        android.widget.Toast.makeText(this, getString(R.string.toast_fp_copied), android.widget.Toast.LENGTH_SHORT).show()
    }

    private fun shareMyContactJson() {
        lifecycleScope.launch {
            val id = io { AppGraph.identityDao.getActive() }
            if (id == null) {
                android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_identity_not_ready), android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }

            val json = JsonContactCodec.encodeContact(
                fingerprint = id.fingerprint,
                onion = id.onion,
                publicKeyBytes = id.publicKeyBytes,
                version = 1
            )

            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, json)
                putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_contact_subject))
            }
            startActivity(Intent.createChooser(send, getString(R.string.share_contact_chooser)))
        }
    }

    private fun showMyContactQr() {
        lifecycleScope.launch {
            val id = io { AppGraph.identityDao.getActive() }
            if (id == null) {
                android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_identity_not_ready), android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }

            val json = JsonContactCodec.encodeContact(
                fingerprint = id.fingerprint,
                onion = id.onion,
                publicKeyBytes = id.publicKeyBytes,
                version = 1
            )

            val i = Intent(this@IdentityActivity, QrShowActivity::class.java).apply {
                putExtra(QrShowActivity.EXTRA_TEXT, json)
                putExtra(QrShowActivity.EXTRA_TITLE, getString(R.string.qr_title_my_contact))
            }
            startActivity(i)
        }
    }

    private fun importFromUri(uri: Uri) {
        lifecycleScope.launch {
            val text = try {
                io {
                    contentResolver.openInputStream(uri)?.use { ins ->
                        ins.readBytes().toString(Charsets.UTF_8)
                    } ?: ""
                }
            } catch (_: Throwable) {
                ""
            }

            if (text.isBlank()) {
                android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_import_failed), android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }
            importFromText(text)
        }
    }

    private fun importFromText(jsonText: String) {
        lifecycleScope.launch {
            val myId = io { AppGraph.identityDao.getActive() }
            if (myId == null) {
                android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_identity_not_ready), android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }

            val contact = try {
                JsonContactCodec.decodeContact(jsonText)
            } catch (_: Throwable) {
                android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_invalid_json), android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }

            val selfFp = FpFormat.canonical(myId.fingerprint)
            if (FpFormat.canonical(contact.fingerprint) == selfFp) {
                android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_self_import_forbidden), android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }

            io<Unit> { AppGraph.contactDao.upsertMergeSafe(contact) }
            android.widget.Toast.makeText(this@IdentityActivity, getString(R.string.toast_contact_imported), android.widget.Toast.LENGTH_SHORT).show()

        }
    }

    private fun handleIncomingIntent(intent: Intent) {
        if (intent.action != Intent.ACTION_SEND) return

        val uri = if (android.os.Build.VERSION.SDK_INT >= 33) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }

        val text = intent.getStringExtra(Intent.EXTRA_TEXT)

        when {
            uri != null -> importFromUri(uri)
            !text.isNullOrBlank() -> importFromText(text)
        }
    }
}
