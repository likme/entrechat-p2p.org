/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface InviteDao {

    @Insert
    suspend fun insert(invite: InviteEntity): Long

    @Query("SELECT * FROM invites WHERE token = :token LIMIT 1")
    suspend fun findByToken(token: String): InviteEntity?

    @Query(
        """
        UPDATE invites
        SET usedAtMs = :usedAtMs, usedByHint = :usedByHint
        WHERE token = :token
          AND usedAtMs IS NULL
          AND expiresAtMs > :nowMs
        """
    )
    suspend fun markUsedIfValid(
        token: String,
        usedAtMs: Long,
        nowMs: Long,
        usedByHint: String?
    ): Int

    @Query("DELETE FROM invites WHERE expiresAtMs <= :nowMs OR usedAtMs IS NOT NULL")
    suspend fun purgeDead(nowMs: Long): Int

    @Query("SELECT COUNT(*) FROM invites WHERE usedAtMs IS NULL AND expiresAtMs > :nowMs")
    suspend fun countActive(nowMs: Long): Int
}
