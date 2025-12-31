/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [
        MessageEntity::class,
        ContactEntity::class,
        IdentityEntity::class,
        InviteEntity::class
    ],
    version = 5,
    exportSchema = false
)
abstract class EntrechatDatabase : RoomDatabase() {
    abstract fun messageDao(): MessageDao
    abstract fun contactDao(): ContactDao
    abstract fun identityDao(): IdentityDao
    abstract fun inviteDao(): InviteDao
}
