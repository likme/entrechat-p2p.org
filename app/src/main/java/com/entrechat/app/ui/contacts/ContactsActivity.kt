/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.contacts

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.Base64
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import kotlinx.coroutines.delay
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.entrechat.app.AppGraph
import com.entrechat.app.EntrechatServiceManager
import com.entrechat.app.R
import com.entrechat.app.config.ProtocolConfig
import com.entrechat.app.databinding.ActivityContactsBinding
import com.entrechat.app.db.ContactEntity
import com.entrechat.app.db.UpsertResult
import com.entrechat.app.ui.chat.ChatActivity
import com.entrechat.app.ui.common.Ec2QrCodec
import com.entrechat.app.ui.common.FpFormat
import com.entrechat.app.ui.common.JsonContactCodec
import com.entrechat.app.ui.common.io
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout


class ContactsActivity : AppCompatActivity() {

companion object {

    private const val MAX_IMPORT_CHARS = 16 * 1024
    private const val MAX_PUBLIC_KEY_BYTES = 32 * 1024

    private const val PREFIX_SINGLE_QR = "ec1|"
    private const val PREFIX_INVITE_QR = "ec2|"

    private const val ERR_EC2_INVALID_QR = "EC2_IMPORT_INVALID_QR"
    private const val ERR_EC2_TOR_NOT_READY = "EC2_IMPORT_TOR_NOT_READY"
    private const val ERR_EC2_INVITE_INVALID = "EC2_IMPORT_INVITE_INVALID"
    private const val ERR_EC2_VERSION_UNSUPPORTED = "EC2_IMPORT_VERSION_UNSUPPORTED"
    private const val ERR_EC2_INVALID_FINGERPRINT = "EC2_IMPORT_INVALID_FINGERPRINT"
    private const val ERR_EC2_INVALID_ONION = "EC2_IMPORT_INVALID_ONION"
    private const val ERR_EC2_MISSING_PUBLIC_KEY = "EC2_IMPORT_MISSING_PUBLIC_KEY"
    private const val ERR_EC2_IMPORT_FAILED = "EC2_IMPORT_FAILED"

    private val FP_HEX40_RE = Regex("^[0-9A-F]{40}$")
    private val ONION_V3_HOST_RE = Regex("^[a-z2-7]{56}\\.onion$", RegexOption.IGNORE_CASE)
    private val HOST_PORT_RE = Regex("^([^:]+)(?::(\\d{1,5}))?$")

    private fun decodePublicKeyB64OrNull(raw: String?): ByteArray? {
        val s = raw?.trim().orEmpty()
        if (s.isBlank()) return null
        if (s.any { it.isWhitespace() }) return null

        val bytes = try {
            Base64.decode(s, Base64.NO_WRAP)
        } catch (_: Throwable) {
            return null
        }

        if (bytes.isEmpty()) return null
        if (bytes.size > MAX_PUBLIC_KEY_BYTES) return null
        return bytes
    }
}



    private lateinit var b: ActivityContactsBinding

    private val adapter = ContactsAdapter(
        onClick = { row ->
            if (row.isNoteToSelf) {
                startActivity(
                    Intent(this, ChatActivity::class.java).apply {
                        putExtra(ChatActivity.EXTRA_IS_NOTE_TO_SELF, true)
                    }
                )
            } else {
                startActivity(
                    Intent(this, ChatActivity::class.java).apply {
                        putExtra(ChatActivity.EXTRA_CONTACT_FP, row.fingerprint)
                    }
                )
            }
        },
        onLongClick = { row ->
            if (!row.isNoteToSelf) showContactActionsDialog(row)
        }
    )

    private var previousOrientation: Int? = null
    private var importProgress: AlertDialog? = null

    private fun showImportProgress() {
        if (importProgress?.isShowing == true) return

        val tv = TextView(this).apply {
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
            text = getString(R.string.import_in_progress)
        }

        // Do NOT lock orientation for progress. Rotation must not interrupt import.
        importProgress = AlertDialog.Builder(this)
            .setView(tv)
            .setCancelable(false)
            .create()
            .also { it.show() }
    }

    private fun hideImportProgress() {
        importProgress?.dismiss()
        importProgress = null
        // Do NOT unlock orientation here. Only review/pending dialogs manage orientation lock.
    }



    private fun lockOrientation() {
        if (previousOrientation != null) return
        previousOrientation = requestedOrientation
        requestedOrientation = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_LOCKED
    }

    private fun unlockOrientation() {
        val prev = previousOrientation ?: return
        requestedOrientation = prev
        previousOrientation = null
    }

    private val openDoc =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri != null) importFromUri(uri)
        }

    private val scanQr =
        registerForActivityResult(ScanContract()) { result ->
            val contents = result.contents?.trim().orEmpty()
            if (contents.isBlank()) return@registerForActivityResult

            if (contents.length > MAX_IMPORT_CHARS) {
                Toast.makeText(this, R.string.toast_import_too_large, Toast.LENGTH_SHORT).show()
                return@registerForActivityResult
            }

            importFromText(contents)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        b = ActivityContactsBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.recycler.adapter = adapter
        b.recycler.layoutManager = LinearLayoutManager(this)

        b.btnImport.setOnClickListener {
            openDoc.launch(arrayOf("application/json", "text/*"))
        }

        b.btnScanQr.setOnClickListener {
            val opts = ScanOptions().apply {
                setPrompt(getString(R.string.contacts_scan_prompt))
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setBeepEnabled(false)
                setOrientationLocked(true)
                setPrompt(getString(R.string.contacts_scan_prompt))
            }
            scanQr.launch(opts)
        }

        b.btnAddManual.setOnClickListener {
            showManualAddDialog()
        }


        handleIncomingIntent(intent)
        refresh()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun handleIncomingIntent(intent: Intent) {
        if (intent.action != Intent.ACTION_SEND) return

        val uri: Uri? = if (Build.VERSION.SDK_INT >= 33) {
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

    private fun refresh() {
        lifecycleScope.launch {
            val myId = io { AppGraph.identityDao.getActive() }
            if (myId == null) {
                Toast.makeText(this@ContactsActivity, R.string.toast_identity_not_ready, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val selfFp = FpFormat.canonical(myId.fingerprint)

            val list = io { AppGraph.contactDao.list(limit = 1000) }

            val noteToSelfRow = ContactRow(
                fingerprint = selfFp,
                fingerprintShort = getString(R.string.chat_title_note_to_self),
                onion = "",
                isNoteToSelf = true
            )

            val items = list.map {
                val label = it.displayName?.trim().takeUnless { n -> n.isNullOrBlank() }
                    ?: FpFormat.short(it.fingerprint)

                ContactRow(
                    fingerprint = it.fingerprint,
                    fingerprintShort = label,
                    onion = it.onion,
                    isNoteToSelf = false
                )
            }

            adapter.submitList(buildList {
                add(noteToSelfRow)
                addAll(items)
            })

            b.txtCount.text = getString(R.string.contacts_count_format, items.size)
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
                Toast.makeText(this@ContactsActivity, R.string.toast_import_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }

            if (text.length > MAX_IMPORT_CHARS) {
                Toast.makeText(this@ContactsActivity, R.string.toast_import_too_large, Toast.LENGTH_SHORT).show()
                return@launch
            }

            importFromText(text)
        }
    }

private fun showManualAddDialog() {

    val fpLayout = TextInputLayout(this).apply {
        hint = getString(R.string.contacts_add_manual_fp_hint)
        isHintEnabled = true
    }
    val fpInput = TextInputEditText(fpLayout.context).apply {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }
    fpLayout.addView(fpInput)

    val onionLayout = TextInputLayout(this).apply {
        hint = getString(R.string.contacts_add_manual_onion_hint)
        isHintEnabled = true
    }
    val onionInput = TextInputEditText(onionLayout.context).apply {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }
    onionLayout.addView(onionInput)

    val pubLayout = TextInputLayout(this).apply {
        hint = getString(R.string.contacts_add_manual_pubkey_hint)
        isHintEnabled = true
    }
    val pubInput = TextInputEditText(pubLayout.context).apply {
        inputType =
            InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        isSingleLine = false
        minLines = 4
        maxLines = 8
        setHorizontallyScrolling(false)
    }
    pubLayout.addView(pubInput)

    val contentInner = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val pad = (16 * resources.displayMetrics.density).toInt()
        setPadding(pad, pad, pad, pad)

        fun spacer(hDp: Int) = TextView(this@ContactsActivity).apply {
            height = (hDp * resources.displayMetrics.density).toInt()
        }

        addView(TextView(this@ContactsActivity).apply {
            text = "Paste the contact data you received."
        })
        addView(spacer(8))

        addView(fpLayout)
        addView(spacer(8))
        addView(onionLayout)
        addView(spacer(8))
        addView(pubLayout)
    }

    val content = ScrollView(this).apply {
        addView(contentInner)
    }

    fun validateFields(): Triple<String?, String?, ByteArray?> {
        val fpCanon = canonicalizeFingerprintOrNull(fpInput.text?.toString())
        val onionCanon = canonicalizeOnionHostPortOrNull(onionInput.text?.toString())
        val pubBytes = decodePublicKeyB64OrNull(pubInput.text?.toString())
        return Triple(fpCanon, onionCanon, pubBytes)
    }

    fun updateInlineErrors() {
        val (fpCanon, onionCanon, pubBytes) = validateFields()

        fpLayout.error = if (fpCanon == null) "Invalid fingerprint" else null
        onionLayout.error = if (onionCanon == null) "Invalid onion address" else null
        pubLayout.error = if (pubBytes == null) "Invalid public key" else null
    }

    val dlg = AlertDialog.Builder(this)
        .setTitle(R.string.contacts_add_manual_title)
        .setView(content)
        .setNegativeButton(R.string.action_cancel, null)
        // override click to avoid auto-dismiss
        .setPositiveButton(R.string.action_import, null)
        .create()

    dlg.setOnShowListener {
        val positive = dlg.getButton(AlertDialog.BUTTON_POSITIVE)

        fun updatePositiveEnabled() {
            val (fpCanon, onionCanon, pubBytes) = validateFields()
            positive.isEnabled = (fpCanon != null && onionCanon != null && pubBytes != null)
        }

        val watcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                updateInlineErrors()
                updatePositiveEnabled()
            }
        }

        fpInput.addTextChangedListener(watcher)
        onionInput.addTextChangedListener(watcher)
        pubInput.addTextChangedListener(watcher)

        updateInlineErrors()
        updatePositiveEnabled()

        positive.setOnClickListener {
            val (fpCanon, onionCanon, pubBytes) = validateFields()
            if (fpCanon == null || onionCanon == null || pubBytes == null) {
                updateInlineErrors()
                return@setOnClickListener
            }

            lifecycleScope.launch {
                val myId = io { AppGraph.identityDao.getActive() }
                if (myId == null) {
                    Toast.makeText(
                        this@ContactsActivity,
                        R.string.toast_identity_not_ready,
                        Toast.LENGTH_SHORT
                    ).show()
                    return@launch
                }

                val selfFp = FpFormat.canonical(myId.fingerprint)
                if (fpCanon == selfFp) {
                    Toast.makeText(
                        this@ContactsActivity,
                        R.string.toast_self_import_forbidden,
                        Toast.LENGTH_SHORT
                    ).show()
                    return@launch
                }

                val draft = ContactEntity(
                    fingerprint = fpCanon,
                    onion = onionCanon,
                    publicKeyBytes = pubBytes,
                    trustLevel = ContactEntity.TRUST_UNVERIFIED
                )

                dlg.dismiss()

                showImportReviewDialog(contactDraft = draft) {
                    lifecycleScope.launch {
                        showImportProgress()
                        try {
                            val result = io { AppGraph.contactDao.upsertMergeSafe(draft) }
                            when (result) {
                                is UpsertResult.Inserted -> {
                                    Toast.makeText(
                                        this@ContactsActivity,
                                        R.string.toast_contact_imported,
                                        Toast.LENGTH_SHORT
                                    ).show()
                                    refresh()
                                }
                                is UpsertResult.NoChange -> {
                                    Toast.makeText(
                                        this@ContactsActivity,
                                        R.string.toast_contact_already_exists,
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                                is UpsertResult.UpdatedUnverified,
                                is UpsertResult.PendingApproval -> {
                                    Toast.makeText(
                                        this@ContactsActivity,
                                        R.string.toast_import_processed,
                                        Toast.LENGTH_SHORT
                                    ).show()
                                    refresh()
                                }
                            }
                        } finally {
                            hideImportProgress()
                        }
                    }
                }
            }
        }
    }

    dlg.show()
}


private fun importFromText(inputText: String) {
    lifecycleScope.launch {
        showImportProgress()
        try {
            if (inputText.length > MAX_IMPORT_CHARS) {
                Toast.makeText(this@ContactsActivity, R.string.toast_import_too_large, Toast.LENGTH_SHORT).show()
                return@launch
            }

            val myId = io { AppGraph.identityDao.getActive() }
            if (myId == null) {
                Toast.makeText(this@ContactsActivity, R.string.toast_identity_not_ready, Toast.LENGTH_SHORT).show()
                return@launch
            }

            val trimmed = inputText.trim()

            if (trimmed.startsWith(PREFIX_INVITE_QR, ignoreCase = true)) {
                // EC2 handles its own progress UI
                hideImportProgress()
                importFromEc2Invite(trimmed, myId.fingerprint)
                return@launch
            }

            val normalizedJson = try {
                if (trimmed.startsWith(PREFIX_SINGLE_QR, ignoreCase = true)) {
                    decodeSingleQrToContactJson(trimmed)
                } else {
                    trimmed
                }
            } catch (_: Throwable) {
                Toast.makeText(this@ContactsActivity, R.string.toast_invalid_qr, Toast.LENGTH_SHORT).show()
                return@launch
            }

            if (normalizedJson.length > MAX_IMPORT_CHARS) {
                Toast.makeText(this@ContactsActivity, R.string.toast_import_too_large, Toast.LENGTH_SHORT).show()
                return@launch
            }

            if (!looksLikeJsonObject(normalizedJson)) {
                Toast.makeText(this@ContactsActivity, R.string.toast_invalid_json, Toast.LENGTH_SHORT).show()
                return@launch
            }

            val contactDraft = try {
                JsonContactCodec.decodeContact(normalizedJson)
            } catch (_: Throwable) {
                Toast.makeText(this@ContactsActivity, R.string.toast_invalid_json, Toast.LENGTH_SHORT).show()
                return@launch
            }

            val selfFp = FpFormat.canonical(myId.fingerprint)
            if (FpFormat.canonical(contactDraft.fingerprint) == selfFp) {
                Toast.makeText(this@ContactsActivity, R.string.toast_self_import_forbidden, Toast.LENGTH_SHORT).show()
                return@launch
            }

            val fpCanon = FpFormat.canonical(contactDraft.fingerprint)

            // Stop spinner before showing a dialog
            hideImportProgress()

            showImportReviewDialog(contactDraft = contactDraft) {
                lifecycleScope.launch {
                    showImportProgress()
                    try {
                        val result = io { AppGraph.contactDao.upsertMergeSafe(contactDraft) }

                        when (result) {
                            is UpsertResult.Inserted -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_contact_imported, Toast.LENGTH_SHORT).show()
                                refresh()
                            }
                            is UpsertResult.NoChange -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_contact_already_exists, Toast.LENGTH_SHORT).show()
                            }
                            is UpsertResult.UpdatedUnverified -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_import_processed, Toast.LENGTH_SHORT).show()
                                refresh()
                            }
                            is UpsertResult.PendingApproval -> {
                                val c = io { AppGraph.contactDao.getByFingerprint(fpCanon) }
                                if (c == null) {
                                    Toast.makeText(this@ContactsActivity, R.string.toast_contact_not_found, Toast.LENGTH_SHORT).show()
                                    return@launch
                                }

                                val pending = PendingIdentity(
                                    onion = c.pendingOnion?.trim(),
                                    publicKeyBytes = c.pendingPublicKeyBytes
                                )

                                showPendingChangeDialog(
                                    existing = c,
                                    pending = pending,
                                    onApprove = {
                                        lifecycleScope.launch {
                                            io<Unit> { AppGraph.contactDao.approvePending(fpCanon) }
                                            Toast.makeText(this@ContactsActivity, R.string.toast_approved, Toast.LENGTH_SHORT).show()
                                            refresh()
                                        }
                                    },
                                    onReject = {
                                        lifecycleScope.launch {
                                            io<Unit> { AppGraph.contactDao.rejectPending(fpCanon) }
                                            Toast.makeText(this@ContactsActivity, R.string.toast_rejected, Toast.LENGTH_SHORT).show()
                                            refresh()
                                        }
                                    }
                                )
                            }
                        }
                    } finally {
                        hideImportProgress()
                    }
                }
            }
        } finally {
            // If we returned early before dialog, this cleans up
            hideImportProgress()
        }
    }
}


private suspend fun importFromEc2Invite(qrText: String, myFingerprint: String) {

    fun toastCode(code: String) {
        Toast.makeText(this@ContactsActivity, code, Toast.LENGTH_SHORT).show()
    }

    withContext(Dispatchers.Main) { showImportProgress() }
    try {
        val parsed = Ec2QrCodec.decode(qrText)
        if (parsed == null) {
            toastCode(ERR_EC2_INVALID_QR)
            return
        }

        val st = EntrechatServiceManager.getState()
        if (st !is EntrechatServiceManager.AppState.TOR_READY) {
            toastCode(ERR_EC2_TOR_NOT_READY)
            return
        }

        val host = parsed.inviteOnion.trim()
        if (!isValidOnionHostPort(host)) {
            toastCode(ERR_EC2_INVALID_ONION)
            return
        }

        val url = "http://$host${ProtocolConfig.INVITE_PATH_PREFIX}${parsed.token}"

        val socks = AppGraph.torManager.getSocksEndpoint()
        val client = AppGraph.buildTorRemoteClient(socks)

        val res = io { client.get(url) }
        if (!res.ok || res.body.isNullOrBlank()) {
            toastCode(ERR_EC2_INVITE_INVALID)
            return
        }

        val json = try {
            JSONObject(res.body)
        } catch (_: Throwable) {
            toastCode(ERR_EC2_INVITE_INVALID)
            return
        }

        if (json.optInt("v") != ProtocolConfig.VERSION_INVITE_V2) {
            toastCode(ERR_EC2_VERSION_UNSUPPORTED)
            return
        }
        if (!json.optBoolean("ok", false)) {
            toastCode(ERR_EC2_INVITE_INVALID)
            return
        }

        val fpCanon = canonicalizeFingerprintOrNull(json.optString("fingerprint", ""))
        if (fpCanon == null) {
            toastCode(ERR_EC2_INVALID_FINGERPRINT)
            return
        }

        val selfFpCanon = canonicalizeFingerprintOrNull(myFingerprint)
        if (selfFpCanon != null && fpCanon == selfFpCanon) {
            Toast.makeText(this@ContactsActivity, R.string.toast_self_import_forbidden, Toast.LENGTH_SHORT).show()
            return
        }

        val onionCanon = canonicalizeOnionHostPortOrNull(
            json.optString("primary_onion", json.optString("onion", ""))
        )
        if (onionCanon == null) {
            toastCode(ERR_EC2_INVALID_ONION)
            return
        }

        val pubB64 = json.optString("pub_b64", "").trim()
        val pubBytes = try {
            Base64.decode(pubB64, Base64.NO_WRAP)
        } catch (_: Throwable) {
            toastCode(ERR_EC2_MISSING_PUBLIC_KEY)
            return
        }

        if (pubBytes.isEmpty()) {
            toastCode(ERR_EC2_MISSING_PUBLIC_KEY)
            return
        }

        val draft = ContactEntity(
            fingerprint = fpCanon,
            onion = onionCanon,
            publicKeyBytes = pubBytes,
            trustLevel = ContactEntity.TRUST_UNVERIFIED
        )

        withContext(Dispatchers.Main) {
            hideImportProgress()
            if (isFinishing || isDestroyed) return@withContext

            showImportReviewDialog(contactDraft = draft) {
                lifecycleScope.launch {
                    showImportProgress()
                    try {
                        val result = try {
                            io { AppGraph.contactDao.upsertMergeSafe(draft) }
                        } catch (_: Throwable) {
                            toastCode(ERR_EC2_IMPORT_FAILED)
                            return@launch
                        }

                        when (result) {
                            is UpsertResult.Inserted -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_contact_imported, Toast.LENGTH_SHORT).show()
                                refresh()
                            }
                            is UpsertResult.NoChange -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_contact_already_exists, Toast.LENGTH_SHORT).show()
                            }
                            is UpsertResult.UpdatedUnverified -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_import_processed, Toast.LENGTH_SHORT).show()
                                refresh()
                            }
                            is UpsertResult.PendingApproval -> {
                                Toast.makeText(this@ContactsActivity, R.string.toast_import_processed, Toast.LENGTH_SHORT).show()
                                refresh()
                            }
                        }

                        startActivity(
                            Intent(this@ContactsActivity, ChatActivity::class.java).apply {
                                putExtra(ChatActivity.EXTRA_CONTACT_FP, fpCanon)
                                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                            }
                        )
                    } finally {
                        hideImportProgress()
                    }
                }
            }
        }
    } catch (_: Throwable) {
        toastCode(ERR_EC2_IMPORT_FAILED)
    } finally {
        withContext(Dispatchers.Main) { hideImportProgress() }
    }
}




    private fun decodeSingleQrToContactJson(qrText: String): String {
        val parsed = QrContactV1.parseLine(qrText)
        val contact = when (parsed) {
            is QrContactV1.ParseLineResult.SingleLine -> parsed.contact
            else -> throw IllegalArgumentException("BAD_QR_KIND")
        }

        val fpCanon = canonicalizeFingerprintOrNull(contact.fingerprint)
            ?: throw IllegalArgumentException("BAD_FP")

        val onionCanon = canonicalizeOnionHostPortOrNull(contact.onion)
            ?: throw IllegalArgumentException("BAD_ONION")

        val pubB64 = contact.publicKeyB64.trim()
        if (pubB64.isBlank()) throw IllegalArgumentException("BAD_PUB")

        return JSONObject().apply {
            put("v", ProtocolConfig.VERSION)
            put("type", ProtocolConfig.TYPE_CONTACT)
            put("fingerprint", fpCanon)
            put("onion", onionCanon)
            put("pub_b64", pubB64)
        }.toString()
    }


    private data class PendingIdentity(
        val onion: String?,
        val publicKeyBytes: ByteArray?
    )

    private fun showImportReviewDialog(contactDraft: ContactEntity, onConfirm: () -> Unit) {
        val fpCanon = FpFormat.canonical(contactDraft.fingerprint)
        val fpShort = FpFormat.short(fpCanon)
        val fullFp = fpCanon

        val onionMasked = maskOnionStrict(contactDraft.onion)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }

        val txtFp = TextView(this).apply {
            text = getString(R.string.contacts_label_fingerprint, fpShort)
        }

        val chkFull = CheckBox(this).apply {
            text = getString(R.string.show_full_fingerprint)
        }

        chkFull.setOnCheckedChangeListener { _, isChecked ->
            txtFp.text = if (isChecked) {
                getString(R.string.contacts_label_fingerprint, fullFp)
            } else {
                getString(R.string.contacts_label_fingerprint, fpShort)
            }
        }

        val txtOnion = TextView(this).apply {
            text = getString(R.string.contacts_label_onion, onionMasked)
        }

        val txtExplain = TextView(this).apply {
            text = getString(R.string.verify_fp_oob)
        }

        content.addView(txtFp)
        content.addView(chkFull)
        content.addView(txtOnion)
        content.addView(txtExplain)

        lockOrientation()

        AlertDialog.Builder(this)
            .setTitle(R.string.import_review_title)
            .setView(content)
            .setOnCancelListener { unlockOrientation() }
            .setNegativeButton(R.string.action_cancel) { _, _ -> unlockOrientation() }
            .setPositiveButton(R.string.action_import) { _, _ ->
                unlockOrientation()
                onConfirm()
            }
            .show()
    }

    private fun showPendingChangeDialog(
        existing: ContactEntity,
        pending: PendingIdentity,
        onApprove: () -> Unit,
        onReject: () -> Unit
    ) {
        val fpShort = FpFormat.short(existing.fingerprint)

        val oldOnion = existing.onion.orEmpty()
        val newOnion = pending.onion?.orEmpty().orEmpty()

        val onionChanged = newOnion.isNotBlank() && !newOnion.equals(oldOnion, ignoreCase = true)

        val keyChanged =
            pending.publicKeyBytes != null &&
                pending.publicKeyBytes.isNotEmpty() &&
                !pending.publicKeyBytes.contentEquals(existing.publicKeyBytes)

        val msg = buildString {
            append(getString(R.string.contacts_changed_intro, fpShort))
            append("\n\n")

            if (onionChanged) {
                append(getString(R.string.contacts_changed_onion_label))
                append("\n")
                append(maskOnionStrict(oldOnion))
                append("\n\u2192 ")
                append(maskOnionStrict(newOnion))
                append("\n\n")
            }

            if (keyChanged) {
                append(getString(R.string.contacts_changed_key_changed))
                append("\n\n")
            }

            if (!onionChanged && !keyChanged) {
                append(getString(R.string.contacts_changed_pending_detected))
                append("\n\n")
            }

            append(getString(R.string.contacts_changed_approve_keeps_trust))
            append("\n")
            append(getString(R.string.verify_fp_oob))

        }

        lockOrientation()

        AlertDialog.Builder(this)
            .setTitle(R.string.contact_changed_title)
            .setMessage(msg)
            .setOnCancelListener { unlockOrientation() }
            .setNegativeButton(R.string.action_reject) { _, _ ->
                unlockOrientation()
                onReject()
            }
            .setPositiveButton(R.string.action_approve) { _, _ ->
                unlockOrientation()
                onApprove()
            }
            .show()
    }

    private fun maskOnionStrict(s: String?): String {
        val t = (s ?: "").trim()
        if (t.isEmpty()) return getString(R.string.common_empty_parens)
        if (t.length <= 18) return t
        val prefix = t.take(6)
        val suffix = t.takeLast(8)
        return "$prefix…$suffix"
    }

    private fun showVerifyDialogFor(fpCanon: String, onVerified: () -> Unit = {}) {
        val fpFull = FpFormat.canonical(fpCanon)
        val tail = fpFull.takeLast(6)

        val input = EditText(this).apply {
            hint = tail
            inputType = InputType.TYPE_CLASS_TEXT
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.contact_not_verified)
            .setMessage(
                getString(R.string.verify_fp_oob) + "\n\n" +
                    fpFull + "\n\n" +
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
                    io<Unit> { AppGraph.contactDao.markVerified(fpFull) }
                    Toast.makeText(this@ContactsActivity, R.string.toast_contact_verified, Toast.LENGTH_SHORT).show()
                    onVerified()
                }
            }
            .show()
    }


    private fun showContactActionsDialog(row: ContactRow) {
        lifecycleScope.launch {
            val existing = io { AppGraph.contactDao.getByFingerprint(row.fingerprint) }
                ?: return@launch

            val verifyLabel = getString(R.string.contacts_action_verify)

            val items = arrayOf(
                getString(R.string.contacts_action_rename),
                getString(R.string.contacts_action_edit_address),
                verifyLabel,
                getString(R.string.contacts_action_delete_contact)
            )

            AlertDialog.Builder(this@ContactsActivity)
                .setTitle(getString(R.string.contacts_actions_title, FpFormat.short(row.fingerprint)))
                .setItems(items) { _, which ->
                    when (which) {
                        0 -> showRenameContactDialog(row)
                        1 -> showEditAddressDialog(row)
                        2 -> {
                            if (existing.trustLevel == ContactEntity.TRUST_VERIFIED) {
                                Toast.makeText(
                                    this@ContactsActivity,
                                    R.string.toast_contact_already_verified,
                                    Toast.LENGTH_SHORT
                                ).show()
                                return@setItems
                            }

                            showVerifyDialogFor(row.fingerprint) {
                                refresh()
                            }
                        }
                        3 -> {
                            AlertDialog.Builder(this@ContactsActivity)
                                .setTitle(R.string.contacts_delete_title)
                                .setMessage(R.string.contacts_delete_body)
                                .setNegativeButton(R.string.action_cancel, null)
                                .setPositiveButton(R.string.action_delete) { _, _ ->
                                    lifecycleScope.launch {
                                        io<Unit> { AppGraph.contactDao.deleteByFingerprint(row.fingerprint) }
                                        Toast.makeText(this@ContactsActivity, R.string.toast_contact_deleted, Toast.LENGTH_SHORT).show()
                                        refresh()
                                    }
                                }
                                .show()
                        }
                    }
                }
                .show()

        }
    }

    private fun showRenameContactDialog(row: ContactRow) {
        lifecycleScope.launch {
            val existing = io { AppGraph.contactDao.getByFingerprint(row.fingerprint) }
            if (existing == null) {
                Toast.makeText(this@ContactsActivity, R.string.toast_contact_not_found, Toast.LENGTH_SHORT).show()
                return@launch
            }

            val et = EditText(this@ContactsActivity).apply {
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
                hint = getString(R.string.contacts_rename_hint)
                setText(existing.displayName.orEmpty())
                setSelection(text?.length ?: 0)
            }

            AlertDialog.Builder(this@ContactsActivity)
                .setTitle(R.string.contacts_rename_title)
                .setView(et)
                .setNegativeButton(R.string.action_cancel, null)
                .setNeutralButton(R.string.action_clear) { _, _ ->
                    lifecycleScope.launch {
                        io<Unit> { AppGraph.contactDao.updateDisplayName(row.fingerprint, null) }
                        refresh()
                    }
                }
                .setPositiveButton(R.string.action_ok) { _, _ ->
                    val name = et.text?.toString()?.trim().orEmpty()
                    val normalized: String? = name.takeIf { it.isNotBlank() }

                    lifecycleScope.launch {
                        io<Unit> { AppGraph.contactDao.updateDisplayName(row.fingerprint, normalized) }
                        refresh()
                    }
                }
                .show()
        }
    }

    private fun showEditAddressDialog(row: ContactRow) {
        val et = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT
            hint = getString(R.string.contacts_address_hint)
            setText(row.onion)
            setSelection(text?.length ?: 0)
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.contacts_address_title)
            .setMessage(R.string.contacts_address_body)
            .setView(et)
            .setNegativeButton(R.string.action_cancel, null)
            .setNeutralButton(R.string.action_clear, null)

            .setPositiveButton(R.string.action_ok) { _, _ ->
                val s = et.text?.toString().orEmpty().trim()
                if (s.isNotEmpty() && !isValidOnionHostPort(s)) {
                    Toast.makeText(this, R.string.toast_invalid_address, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    io<Unit> {
                        val dao = AppGraph.contactDao
                        val c = dao.getByFingerprint(row.fingerprint) ?: return@io
                        dao.upsertMergeSafe(c.copy(onion = s))
                    }
                    Toast.makeText(this@ContactsActivity, R.string.toast_address_saved, Toast.LENGTH_SHORT).show()
                    refresh()
                }
            }
            .show()
    }

    private fun isValidOnionHostPort(s: String): Boolean {
        val t = s.trim()
        if (t.isBlank()) return false
        if (t.startsWith("http://", true) || t.startsWith("https://", true)) return false
        if (t.contains("/") || t.contains("?") || t.contains("#")) return false

        val m = HOST_PORT_RE.matchEntire(t) ?: return false
        val host = m.groupValues[1].trim()
        val portStr = m.groupValues.getOrNull(2)?.trim().orEmpty()

        if (!ONION_V3_HOST_RE.matches(host)) return false
        if (portStr.isNotBlank()) {
            val p = portStr.toIntOrNull() ?: return false
            if (p !in 1..65535) return false
        }
        return true
    }

    private fun canonicalizeFingerprintOrNull(raw: String?): String? {
        val s = raw
            ?.trim()
            ?.replace("\\s+".toRegex(), "")
            ?.uppercase()
            ?: return null

        if (s.isEmpty()) return null
        if (!FP_HEX40_RE.matches(s)) return null
        return s
    }

    private fun canonicalizeOnionHostPortOrNull(raw: String?): String? {
        val t = raw?.trim()?.lowercase() ?: return null
        if (t.isEmpty()) return null
        if (!isValidOnionHostPort(t)) return null

        val m = HOST_PORT_RE.matchEntire(t) ?: return null
        val host = m.groupValues[1].trim().lowercase()
        val portStr = m.groupValues.getOrNull(2)?.trim().orEmpty()
        return if (portStr.isBlank()) host else "$host:$portStr"
    }

    private fun looksLikeJsonObject(s: String): Boolean {
        val t = s.trim()
        if (t.length < 2) return false
        return t.startsWith("{") && t.endsWith("}")
    }

}
