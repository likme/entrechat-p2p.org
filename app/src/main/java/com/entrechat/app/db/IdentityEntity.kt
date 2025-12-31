/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Local identity (device-owned).
 *
 * privateKeyBlobEncrypted:
 * - encrypted OpenPGP secret key ring bytes
 * - encryption handled by Keystore+PIN layer (not by Room)
 */
@Entity(
    tableName = "identities",
    indices = [
        Index(value = ["isActive"])
    ]
)
data class IdentityEntity(
    @PrimaryKey
    val fingerprint: String,              // HEX uppercase, no spaces

    val onion: String = "",                    // v3 .onion for this identity

    val publicKeyBytes: ByteArray,        // OpenPGP binary public key ring bytes

    val privateKeyBlobEncrypted: ByteArray, // encrypted secret key ring bytes

    val isActive: Boolean = true,

    val createdAt: Long = System.currentTimeMillis()
)
