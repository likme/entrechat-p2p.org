/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.chat

import android.os.Bundle
import android.util.LruCache
import android.util.Log
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.addTextChangedListener
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.SimpleItemAnimator
import com.entrechat.app.AppGraph
import com.entrechat.app.R
import com.entrechat.app.databinding.ActivityChatBinding
import com.entrechat.app.db.ContactEntity
import com.entrechat.app.db.MessageEntity
import com.entrechat.app.network.OutgoingMessageSender
import com.entrechat.app.tor.TorState
import com.entrechat.app.ui.common.FpFormat
import com.entrechat.app.EntrechatServiceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_CONTACT_FP = "contact_fp"
        const val EXTRA_IS_NOTE_TO_SELF = "is_note_to_self"
        private const val LIMIT = 500
        private const val PREVIEW_CACHE_SIZE = 512
        private const val TAG = "ChatActivity"
    }

    private lateinit var binding: ActivityChatBinding
    private val adapter = ChatAdapter()

    private var contactFp: String = ""
    private var conversationId: String = ""
    private var isNoteToSelf: Boolean = false

    private var observeJob: Job? = null
    private var torObserveJob: Job? = null
    private var serviceObserveJob: Job? = null

    // RAM-only cache. No persistence. Keyed by msgId.
    private val previewCache = LruCache<String, String>(PREVIEW_CACHE_SIZE)

    // Sending policy flags (no sensitive logs).
    // Trust policy blocks sending. Tor readiness does NOT block sending (messages will be queued).
    private var blockSending: Boolean = false
    private var warnedBlocked: Boolean = false

    private enum class BlockReason { NONE, CONTACT_CHANGED, NOT_VERIFIED }
    private var blockReason: BlockReason = BlockReason.NONE

    // UI-only network banner text derived from TorState.
    private var torBannerText: String? = null
    private var lastTorState: TorState? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityChatBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        binding.rvMessages.layoutManager = layoutManager
        binding.rvMessages.adapter = adapter
        binding.rvMessages.setHasFixedSize(true)
        (binding.rvMessages.itemAnimator as? SimpleItemAnimator)?.supportsChangeAnimations = false

        binding.edtMessage.addTextChangedListener { refreshSendEnabled() }

        binding.edtMessage.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEND) {
                if (binding.btnSend.isEnabled) binding.btnSend.performClick()
                true
            } else {
                false
            }
        }

        isNoteToSelf = intent.getBooleanExtra(EXTRA_IS_NOTE_TO_SELF, false)
        contactFp = intent.getStringExtra(EXTRA_CONTACT_FP)?.trim().orEmpty()

        if (!isNoteToSelf) {
            if (contactFp.isBlank()) {
                Toast.makeText(this, R.string.toast_missing_contact, Toast.LENGTH_SHORT).show()
                finish()
                return
            }
            contactFp = FpFormat.canonical(contactFp)
        } else {
            // Avoid accidental use.
            contactFp = ""
        }

        binding.btnSend.setOnClickListener { sendMessage() }

        // The banner is used for both trust and network state.
        // Click is reserved for trust remediation actions only.
        binding.txtTrustBanner.setOnClickListener {
            if (isNoteToSelf) return@setOnClickListener
            when (blockReason) {
                BlockReason.NOT_VERIFIED -> showVerifyDialog()
                BlockReason.CONTACT_CHANGED -> showContactChangedDialog()
                else -> Unit
            }
        }

        refreshSendEnabled()

        lifecycleScope.launch {
            val identity = withContext(Dispatchers.IO) { AppGraph.identityDao.getActive() }
            if (identity == null) {
                Toast.makeText(this@ChatActivity, R.string.toast_identity_not_ready, Toast.LENGTH_SHORT).show()
                finish()
                return@launch
            }

            val selfFp = FpFormat.canonical(identity.fingerprint)

            if (isNoteToSelf) {
                conversationId = selfFp
                binding.toolbar.setTitle(R.string.chat_title_note_to_self)
                binding.toolbar.subtitle = FpFormat.short(conversationId)

                blockSending = false
                warnedBlocked = false
                blockReason = BlockReason.NONE

                // Note-to-self does not need trust banner.
                setBanner(null)
                refreshSendEnabled()
            } else {
                conversationId = contactFp

                val contact = withContext(Dispatchers.IO) {
                    AppGraph.contactDao.getByFingerprint(contactFp)
                }
                applyConversationTitle(contact)

                // Initial trust policy evaluation.
                reevaluateTrustPolicy()
            }

            startObserving(selfFp = selfFp)
            startObservingTorState()
            startObservingServiceState()
        }
    }

    override fun onResume() {
        super.onResume()
        // Re-check trust/change-state and title after returning from Contacts.
        if (!isNoteToSelf && contactFp.isNotBlank()) {
            reevaluateTrustPolicy()
        }
    }

    override fun onStop() {
        super.onStop()
        observeJob?.cancel()
        observeJob = null

        torObserveJob?.cancel()
        torObserveJob = null

        serviceObserveJob?.cancel()
        serviceObserveJob = null
    }

    private fun refreshSendEnabled() {
        val hasText = !binding.edtMessage.text.isNullOrBlank()
        binding.btnSend.isEnabled = hasText && !blockSending
    }

    private fun setBanner(text: String?) {
        val show = !text.isNullOrBlank()
        binding.txtTrustBanner.visibility = if (show) View.VISIBLE else View.GONE
        binding.txtTrustBanner.text = text.orEmpty()
    }

    private fun renderTopBanner() {
        if (isNoteToSelf) {
            setBanner(null)
            return
        }

        val trustText = when (blockReason) {
            BlockReason.CONTACT_CHANGED -> getString(R.string.chat_banner_contact_changed)
            BlockReason.NOT_VERIFIED -> getString(R.string.chat_banner_contact_not_verified)
            BlockReason.NONE -> null
        }

        val text = when {
            !trustText.isNullOrBlank() -> trustText
            !torBannerText.isNullOrBlank() -> torBannerText
            else -> null
        }

        setBanner(text)
    }

    private fun applyConversationTitle(contact: ContactEntity?) {
        if (isNoteToSelf) return

        val name = contact?.displayName?.trim().takeUnless { it.isNullOrBlank() }
        if (name != null) {
            binding.toolbar.title = name
            binding.toolbar.subtitle = FpFormat.short(contactFp)
        } else {
            binding.toolbar.setTitle(R.string.chat_title)
            binding.toolbar.subtitle = FpFormat.short(contactFp)
        }
    }

    private fun reevaluateTrustPolicy() {
        lifecycleScope.launch {
            val contact = withContext(Dispatchers.IO) {
                AppGraph.contactDao.getByFingerprint(contactFp)
            }

            // Keep title in sync with local rename.
            applyConversationTitle(contact)

            val changeState = contact?.changeState ?: 0
            val trustLevel = contact?.trustLevel ?: 0

            when {
                contact == null -> {
                    blockSending = true
                    blockReason = BlockReason.NOT_VERIFIED
                }
                changeState != 0 -> {
                    blockSending = true
                    blockReason = BlockReason.CONTACT_CHANGED
                }
                trustLevel == ContactEntity.TRUST_UNVERIFIED -> {
                    blockSending = true
                    blockReason = BlockReason.NOT_VERIFIED
                }
                else -> {
                    blockSending = false
                    blockReason = BlockReason.NONE
                }
            }

            // If sending is no longer blocked, allow the long warning toast again.
            if (!blockSending) warnedBlocked = false

            renderTopBanner()
            refreshSendEnabled()
        }
    }

    private fun startObservingTorState() {
        if (torObserveJob?.isActive == true) return

        torObserveJob = lifecycleScope.launch {
            AppGraph.torManager.state.collect { st ->
                Log.i(TAG, "TorState UI = ${st::class.java.simpleName} st=$st")
                lastTorState = st
                torBannerText = torStateToBannerText(st)
                renderTopBanner()
            }
        }
    }

    private fun startObservingServiceState() {
        if (serviceObserveJob?.isActive == true) return

        serviceObserveJob = lifecycleScope.launch {
            EntrechatServiceManager.stateFlow.collect { st ->
                Log.i(TAG, "ServiceState UI = ${st::class.java.simpleName} st=$st")

                // Only show service state when there is no trust block and Tor banner is empty.
                // Minimal: map service state to banner text.
                torBannerText = when (st) {
                    is EntrechatServiceManager.AppState.INIT ->
                        "Service stopped"

                    is EntrechatServiceManager.AppState.TOR_STARTING -> {
                        val d = st.detail?.trim().takeUnless { it.isNullOrBlank() }
                        if (d != null) "Starting ($d)…" else "Starting…"
                    }

                    is EntrechatServiceManager.AppState.TOR_READY -> {
                        val r = st.runtime
                        "Ready • ${FpFormat.short(r.onion)} • socks ${r.socksHost}:${r.socksPort}"
                    }

                    is EntrechatServiceManager.AppState.ERROR -> {
                        val d = st.detail?.trim().takeUnless { it.isNullOrBlank() }
                        val base = "Error: ${st.code}"
                        if (d != null) "$base ($d)" else base
                    }
                }

                renderTopBanner()
            }
        }
    }


    /**
     * Tor UI rules:
     * - onionHint may be displayed, but it must be explicitly "known" and not treated as reachable.
     * - Only TorState.Ready implies reachability.
     */
    private fun torStateToBannerText(st: TorState): String? {
        fun hintSuffix(h: String?): String {
            val v = h?.trim().orEmpty()
            return if (v.isBlank()) "" else " • known onion: ${FpFormat.short(v)}"
        }

        return when (st) {
            is TorState.Stopped ->
                "Tor stopped" + hintSuffix(st.onionHint)

            is TorState.Starting ->
                "Tor starting…" + hintSuffix(st.onionHint)

            is TorState.Bootstrapping -> {
                val p = st.progress.coerceIn(0, 100)
                val s = st.summary?.trim().takeUnless { it.isNullOrBlank() }
                val extra = if (s != null) " ($s)" else ""
                "Tor bootstrap $p%$extra" + hintSuffix(st.onionHint)
            }

            is TorState.TorReady ->
                "Tor ready • service not published" + hintSuffix(st.onionHint)

            is TorState.HiddenServicePublishing ->
                "Publishing onion… (not reachable yet)" + hintSuffix(st.onionHint)

            is TorState.Ready ->
                "Reachable" + hintSuffix(st.onionHint)

            is TorState.Error -> {
                val d = st.detail?.trim().takeUnless { it.isNullOrBlank() }
                val base = "Tor error: ${st.code}"
                (if (d != null) "$base ($d)" else base) + hintSuffix(st.onionHint)
            }
        }
    }

    private fun showVerifyDialog() {
        if (contactFp.isBlank()) return

        val fpFull = contactFp
        val tail = fpFull.takeLast(6)

        val input = android.widget.EditText(this).apply {
            hint = tail
        }

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.chat_banner_contact_not_verified)
            .setMessage(
                getString(R.string.verify_fp_oob) + "\n\n" + fpFull + "\n\n" +
                    getString(R.string.chat_verify_enter_suffix, 6)
            )
            .setView(input)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_ok) { _, _ ->
                val typed = input.text?.toString().orEmpty().trim()
                if (!typed.equals(tail, ignoreCase = true)) {
                    Toast.makeText(this, R.string.toast_verify_suffix_mismatch, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        AppGraph.contactDao.markVerified(contactFp)
                    }
                    reevaluateTrustPolicy()
                }
            }
            .show()
    }

    private fun showContactChangedDialog() {
        if (contactFp.isBlank()) return

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.chat_banner_contact_changed)
            .setMessage(getString(R.string.contacts_changed_pending_detected) + "\n\n" + getString(R.string.verify_fp_oob))
            .setNegativeButton(R.string.action_reject) { _, _ ->
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        AppGraph.contactDao.rejectPending(contactFp)
                    }
                    reevaluateTrustPolicy()
                }
            }
            .setPositiveButton(R.string.action_approve) { _, _ ->
                lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        AppGraph.contactDao.approvePending(contactFp)
                    }
                    reevaluateTrustPolicy()
                }
            }
            .show()
    }

    private fun startObserving(selfFp: String) {
        if (conversationId.isBlank()) return
        if (observeJob?.isActive == true) return

        observeJob = lifecycleScope.launch {
            AppGraph.messageDao
                .observeConversation(convId = conversationId, limit = LIMIT)
                .collect { messages ->

                    val shouldScroll = isAtBottom()

                    // Decrypt previews off the UI thread.
                    val rows = withContext(Dispatchers.IO) {
                        messages.map { e ->
                            val cached = previewCache.get(e.msgId)
                            if (cached != null) {
                                ChatRow(
                                    msgId = e.msgId,
                                    direction = e.direction,
                                    createdAt = e.createdAt,
                                    status = e.status,
                                    bodyPreview = cached
                                )
                            } else {
                                val preview = decryptBodyPreviewBestEffort(
                                    selfFp = selfFp,
                                    e = e
                                )
                                previewCache.put(e.msgId, preview)
                                ChatRow(
                                    msgId = e.msgId,
                                    direction = e.direction,
                                    createdAt = e.createdAt,
                                    status = e.status,
                                    bodyPreview = preview
                                )
                            }
                        }
                    }

                    adapter.submitList(rows) {
                        if (shouldScroll) scrollToBottom()
                    }

                    // If contact metadata changed (pending onion), update banner and block state.
                    if (!isNoteToSelf) {
                        reevaluateTrustPolicy()
                    }

                }
        }
    }

    /**
     * UI rule:
     * - Try to decrypt.
     * - If decryption fails, do not display "(encrypted)" as if it were content.
     *   Return a neutral placeholder.
     */
    private fun decryptBodyPreviewBestEffort(
        selfFp: String,
        e: MessageEntity
    ): String {
        val raw = e.ciphertextBase64?.trim().orEmpty()
        val pgpB64 = extractPgpB64(raw)
        if (pgpB64 == null) {
            Log.w(TAG, "preview: unsupported ciphertext head='${raw.take(32)}'")
            return getString(R.string.chat_preview_unsupported)
        }

        val peerFp = if (isNoteToSelf) conversationId else contactFp
        val senderFp = if (e.direction == "IN") peerFp else selfFp
        val recipientFp = selfFp

        val jo = AppGraph.outgoingSender.decryptForDisplay(
            senderFp = senderFp,
            recipientFp = recipientFp,
            payloadPgpB64 = pgpB64
        ) ?: return getString(R.string.chat_preview_unreadable)

        val body =
            jo.optString("body", "").trim()
                .ifBlank { jo.optString("text", "").trim() }
                .ifBlank { jo.optString("msg", "").trim() }

        return if (body.isBlank()) getString(R.string.chat_preview_unreadable) else body
    }

    private fun extractPgpB64(cipherField: String?): String? {
        val raw = cipherField?.trim().orEmpty()
        if (raw.isBlank()) return null

        fun cleanB64(s: String): String? {
            val v = s.trim()
                .replace("\n", "")
                .replace("\r", "")
                .replace(" ", "")
            return v.takeIf { it.isNotBlank() }
        }

        // Fast path: "v1|pgp=<b64>" where <b64> may run until end-of-string
        run {
            val i = raw.indexOf("v1|pgp=")
            if (i >= 0) {
                val after = raw.substring(i + "v1|pgp=".length)
                val cut = after.indexOf('|')
                val b64 = if (cut >= 0) after.substring(0, cut) else after
                val cleaned = cleanB64(b64)
                if (cleaned != null) return cleaned
            }
        }

        // Alternate tag: v1|pgp_b64=
        run {
            val i = raw.indexOf("v1|pgp_b64=")
            if (i >= 0) {
                val after = raw.substring(i + "v1|pgp_b64=".length)
                val cut = after.indexOf('|')
                val b64 = if (cut >= 0) after.substring(0, cut) else after
                val cleaned = cleanB64(b64)
                if (cleaned != null) return cleaned
            }
        }

        // Generic tagged format split by '|'
        if (raw.contains('|')) {
            val parts = raw.split('|')
            for (p in parts) {
                val t = p.trim()
                if (t.startsWith("pgp=")) {
                    val cleaned = cleanB64(t.substringAfter("pgp="))
                    if (cleaned != null) return cleaned
                }
                if (t.startsWith("pgp_b64=")) {
                    val cleaned = cleanB64(t.substringAfter("pgp_b64="))
                    if (cleaned != null) return cleaned
                }
            }
        }

        return null
    }

    private fun isAtBottom(): Boolean {
        val lm = binding.rvMessages.layoutManager as? LinearLayoutManager ?: return true
        val count = adapter.itemCount
        if (count <= 0) return true
        val lastVisible = lm.findLastCompletelyVisibleItemPosition()
        return lastVisible >= count - 2
    }

    private fun scrollToBottom() {
        val count = adapter.itemCount
        if (count <= 0) return
        binding.rvMessages.post {
            val c = adapter.itemCount
            if (c > 0) binding.rvMessages.scrollToPosition(c - 1)
        }
    }

    private fun sendMessage() {
        if (!isNoteToSelf && blockSending) {
            val resId = when (blockReason) {
                BlockReason.CONTACT_CHANGED -> R.string.toast_sending_blocked_contact_changed
                BlockReason.NOT_VERIFIED -> R.string.toast_sending_disabled
                else -> R.string.toast_sending_disabled
            }

            val len = if (!warnedBlocked) Toast.LENGTH_LONG else Toast.LENGTH_SHORT
            warnedBlocked = true
            Toast.makeText(this@ChatActivity, resId, len).show()
            return
        }

        val text = binding.edtMessage.text?.toString().orEmpty().trim()
        if (text.isBlank()) return

        binding.edtMessage.setText("")

        lifecycleScope.launch {
            val result: OutgoingMessageSender.SendResult? = try {
                withContext(Dispatchers.IO) {
                    if (isNoteToSelf) {
                        AppGraph.outgoingSender.sendNoteToSelf(text)
                    } else {
                        AppGraph.outgoingSender.send(contactFp, text)
                    }
                }
            } catch (_: Throwable) {
                null
            }

            when (result) {
                null -> Toast.makeText(
                    this@ChatActivity,
                    R.string.toast_message_not_sent,
                    Toast.LENGTH_SHORT
                ).show()

                is OutgoingMessageSender.SendResult.Sent -> Unit

                is OutgoingMessageSender.SendResult.QueuedTorNotReady,
                is OutgoingMessageSender.SendResult.QueuedLocalNotReady,
                is OutgoingMessageSender.SendResult.QueuedHttpFail -> {
                    val resId = if (isNoteToSelf) {
                        R.string.toast_internal_error
                    } else {
                        R.string.toast_message_queued
                    }
                    Toast.makeText(this@ChatActivity, resId, Toast.LENGTH_SHORT).show()
                }

                is OutgoingMessageSender.SendResult.FailedContactNotVerified -> {
                    Toast.makeText(
                        this@ChatActivity,
                        R.string.toast_sending_disabled,
                        Toast.LENGTH_LONG
                    ).show()
                }

                is OutgoingMessageSender.SendResult.FailedMissingAddress,
                is OutgoingMessageSender.SendResult.FailedBadAddress,
                is OutgoingMessageSender.SendResult.FailedBlockedDirectHttp,
                is OutgoingMessageSender.SendResult.FailedCryptoError -> {
                    Toast.makeText(
                        this@ChatActivity,
                        R.string.toast_message_not_sent,
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }

    }
}
