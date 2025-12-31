/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.entrechat.app.crypto.DbPassphraseProvider
import net.sqlcipher.database.SupportFactory

object DatabaseFactory {

    private const val DB_NAME = "entrechat.db"

    private val MIGRATION_2_3 = object : Migration(2, 3) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE contacts ADD COLUMN trustLevel INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE contacts ADD COLUMN changeState INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE contacts ADD COLUMN pendingOnion TEXT")
            db.execSQL("ALTER TABLE contacts ADD COLUMN pendingPublicKeyBytes BLOB")
        }
    }

    private val MIGRATION_3_4 = object : Migration(3, 4) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE contacts ADD COLUMN displayName TEXT")
        }
    }

    private val MIGRATION_4_5 = object : Migration(4, 5) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS invites (
                    token TEXT NOT NULL,
                    createdAtMs INTEGER NOT NULL,
                    expiresAtMs INTEGER NOT NULL,
                    usedAtMs INTEGER,
                    usedByHint TEXT,
                    PRIMARY KEY(token)
                )
                """.trimIndent()
            )
            db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_invites_token ON invites(token)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_invites_expiresAtMs ON invites(expiresAtMs)")
            db.execSQL("CREATE INDEX IF NOT EXISTS index_invites_usedAtMs ON invites(usedAtMs)")
        }
    }


    @Volatile
    private var instance: EntrechatDatabase? = null

    fun get(context: Context, passphraseProvider: DbPassphraseProvider): EntrechatDatabase {
        return instance ?: synchronized(this) {
            instance ?: build(context, passphraseProvider).also { instance = it }
        }
    }

    private fun build(context: Context, passphraseProvider: DbPassphraseProvider): EntrechatDatabase {
        val passphrase = passphraseProvider.getPassphrase()
        return try {
            val factory = SupportFactory(passphrase)

            val builder = Room.databaseBuilder(
                context.applicationContext,
                EntrechatDatabase::class.java,
                DB_NAME
            )
                .openHelperFactory(factory)
                .addMigrations(MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)


            if (isDebuggable(context)) {
                builder.fallbackToDestructiveMigration(dropAllTables = true)
            }

            builder.build()
        } finally {
            runCatching { passphrase.fill(0) }
        }
    }

    private fun isDebuggable(context: Context): Boolean {
        return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
}
