/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface IdentityDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun upsert(identity: IdentityEntity)

    @Query("SELECT * FROM identities WHERE fingerprint = :fingerprint LIMIT 1")
    fun getByFingerprint(fingerprint: String): IdentityEntity?

    @Query("SELECT * FROM identities WHERE isActive = 1 LIMIT 1")
    fun getActive(): IdentityEntity?

    @Query("UPDATE identities SET isActive = 0")
    fun deactivateAll()

    @Query("UPDATE identities SET isActive = 1 WHERE fingerprint = :fingerprint")
    fun setActive(fingerprint: String)

    @Query("DELETE FROM identities WHERE fingerprint = :fingerprint")
    fun deleteByFingerprint(fingerprint: String)

    @Query("DELETE FROM identities")
    fun deleteAll()
}
