/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "invites",
    indices = [
        Index(value = ["token"], unique = true),
        Index(value = ["createdAtMs"]),
        Index(value = ["expiresAtMs"]),
        Index(value = ["usedAtMs"])
    ]
)

data class InviteEntity(
    @PrimaryKey
    val token: String,

    val createdAtMs: Long,

    val expiresAtMs: Long,

    val usedAtMs: Long? = null,

    val usedByHint: String? = null
) {
    val isUsed: Boolean
        get() = usedAtMs != null

    fun isExpired(nowMs: Long): Boolean =
        nowMs >= expiresAtMs
}
