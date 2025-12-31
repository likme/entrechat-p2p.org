/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * v1 contact imported via QR.
 *
 * Stores only what is needed to send/verify:
 * - fingerprint (primary key)
 * - onion address (Tor v3 host[:port] canonical form, no scheme, no path, no query)
 * - public key bytes (OpenPGP binary)
 *
 * Local UX-only metadata:
 * - displayName: optional local alias for the contact (never shared, never signed)
 *
 * TOFU + explicit pinning support:
 * - trustLevel: whether the currently stored identity is user-pinned/verified
 * - changeState + pending* fields: track detected changes without silently overwriting pinned data
 */
@Entity(
    tableName = "contacts",
    indices = [
        Index(value = ["onion"])
    ]
)
data class ContactEntity(
    @PrimaryKey
    val fingerprint: String,   // HEX uppercase, no spaces

    /**
     * Tor v3 onion in canonical host[:port] form only.
     * Examples:
     * - abcdef...xyz.onion
     * - abcdef...xyz.onion:12345
     *
     * Must not contain URL scheme (http/https), userinfo, path, query, or fragment.
     */
    val onion: String,

    val publicKeyBytes: ByteArray,

    /**
     * Optional local display name for UX only.
     *
     * - Never transmitted
     * - Never signed
     * - Never used for trust or cryptographic decisions
     * - Nullable: null means fallback to fingerprint short form
     */
    val displayName: String? = null,

    /**
     * Trust state for explicit pinning.
     * 0 = UNVERIFIED (default, TOFU only)
     * 1 = VERIFIED (explicitly pinned by user)
     */
    val trustLevel: Int = TRUST_UNVERIFIED,

    /**
     * Change tracking state for pinned contacts.
     * 0 = NONE
     * 1 = KEY_CHANGED
     * 2 = ONION_CHANGED
     * 3 = BOTH
     */
    val changeState: Int = CHANGE_NONE,

    /**
     * If a change is detected (key/onion) for a pinned contact, store the new values here
     * until the user explicitly accepts/rejects the update.
     */
    val pendingOnion: String? = null,
    val pendingPublicKeyBytes: ByteArray? = null,

    val createdAt: Long = System.currentTimeMillis()
) {
    companion object {
        // trustLevel values
        const val TRUST_UNVERIFIED: Int = 0
        const val TRUST_VERIFIED: Int = 1

        // changeState values
        const val CHANGE_NONE: Int = 0
        const val CHANGE_KEY_CHANGED: Int = 1
        const val CHANGE_ONION_CHANGED: Int = 2
        const val CHANGE_BOTH: Int = 3
    }
}
