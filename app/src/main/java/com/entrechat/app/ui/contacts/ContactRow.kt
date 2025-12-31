/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.contacts

data class ContactRow(
    val fingerprint: String,
    val fingerprintShort: String,
    val onion: String,          // raw onion host[:port], may be blank
    val isNoteToSelf: Boolean,

    // UI indicators (must reflect DB fields)
    val trustLevel: Int = TRUST_UNVERIFIED,
    val changeState: Int = CHANGE_NONE
) {
    val isVerified: Boolean get() = trustLevel == TRUST_VERIFIED
    val isChanged: Boolean get() = changeState != CHANGE_NONE

    val onionMasked: String
        get() = maskOnion(onion)

    val statusLabel: String
        get() = when {
            isChanged -> "Changed"
            isVerified -> "Verified"
            else -> "Unverified"
        }

    companion object {
        // Keep aligned with ContactEntity semantics
        const val TRUST_UNVERIFIED = 0
        const val TRUST_VERIFIED = 1

        const val CHANGE_NONE = 0
        const val CHANGE_KEY_CHANGED = 1
        const val CHANGE_ONION_CHANGED = 2
        const val CHANGE_BOTH = 3

        /**
         * Masks onion host while keeping :port if present.
         * Example: abcdef…wxyz.onion:1234
         */
        fun maskOnion(raw: String): String {
            val s = raw.trim()
            if (s.isEmpty()) return ""

            val host = s.substringBefore(":")
            val port = s.substringAfter(":", missingDelimiterValue = "").trim()

            val maskedHost = when {
                host.length <= 14 -> host
                else -> host.take(6) + "…" + host.takeLast(6)
            }

            return if (port.isNotBlank()) "$maskedHost:$port" else maskedHost
        }
    }
}
