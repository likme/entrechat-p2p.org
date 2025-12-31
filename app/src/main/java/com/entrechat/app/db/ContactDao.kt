/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update

/**
 * Upsert results for safe TOFU-style contact import with explicit pinning.
 */
sealed class UpsertResult {
    data object Inserted : UpsertResult()
    data object NoChange : UpsertResult()

    /**
     * Existing contact is NOT verified. Incoming identity differs and was applied directly (TOFU refresh).
     */
    data object UpdatedUnverified : UpsertResult()

    /**
     * Incoming identity differs from pinned (VERIFIED) fields.
     * The differing values were stored in pending* fields for explicit user approval.
     */
    data class PendingApproval(
        val keyChanged: Boolean,
        val onionChanged: Boolean
    ) : UpsertResult()
}

@Dao
interface ContactDao {

    // Legacy internal path. Do not call directly from contact import flows.
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertReplaceInternal(contact: ContactEntity)

    /**
     * Safe insert path: does not overwrite an existing row.
     * Returns rowId or -1 when ignored due to conflict.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    fun insertIgnore(contact: ContactEntity): Long

    @Update
    fun update(contact: ContactEntity)

    /**
     * Minimal synchronous getter (matches current DAO usage style).
     */
    @Query("SELECT * FROM contacts WHERE fingerprint = :fp LIMIT 1")
    fun getByFingerprint(fp: String): ContactEntity?

    @Query("SELECT * FROM contacts ORDER BY createdAt DESC LIMIT :limit")
    fun list(limit: Int = 100): List<ContactEntity>

    @Query("SELECT * FROM contacts WHERE trustLevel = 1 ORDER BY createdAt DESC")
    fun listVerified(): List<ContactEntity>

    @Query("SELECT EXISTS(SELECT 1 FROM contacts WHERE fingerprint = :fp)")
    fun exists(fp: String): Boolean

    @Query("DELETE FROM contacts WHERE fingerprint = :fp")
    fun deleteByFingerprint(fp: String)

    @Query("UPDATE contacts SET onion = '' WHERE fingerprint = :fp")
    fun clearOnion(fp: String)

    /**
     * Local UX-only: set or clear display name.
     * - name = null clears the alias.
     */
    @Query("UPDATE contacts SET displayName = :name WHERE fingerprint = :fp")
    fun updateDisplayName(fp: String, name: String?)

    @Query("UPDATE contacts SET displayName = NULL WHERE fingerprint = :fp")
    fun clearDisplayName(fp: String)

    @Query("DELETE FROM contacts")
    fun deleteAll()

    @Query("UPDATE contacts SET trustLevel = 1 WHERE fingerprint = :fp")
    fun markVerified(fp: String)

    @Query("UPDATE contacts SET trustLevel = 0 WHERE fingerprint = :fp")
    fun markUnverified(fp: String)

    /**
     * Safe import upsert:
     * - New contact: insert as UNVERIFIED, no pending changes.
     * - Existing contact:
     *   - If VERIFIED: never overwrite onion/publicKeyBytes; store diffs in pending fields and set changeState.
     *   - If UNVERIFIED: apply diffs directly (TOFU refresh), clear pending, keep UNVERIFIED.
     *
     * displayName is local UX-only and must never be overwritten by imports.
     */
    @Transaction
    fun upsertMergeSafe(incoming: ContactEntity): UpsertResult {
        val fp = incoming.fingerprint.trim().uppercase()
        val existing = getByFingerprint(fp)

        val incomingOnion = incoming.onion.trim()
        val incomingPub = incoming.publicKeyBytes

        // New contact.
        if (existing == null) {
            val initialTrust =
                if (incoming.trustLevel == ContactEntity.TRUST_VERIFIED)
                    ContactEntity.TRUST_VERIFIED
                else
                    ContactEntity.TRUST_UNVERIFIED

            val toInsert = incoming.copy(
                fingerprint = fp,
                onion = incomingOnion,
                displayName = null,
                trustLevel = ContactEntity.TRUST_UNVERIFIED,
                changeState = ContactEntity.CHANGE_NONE,
                pendingOnion = null,
                pendingPublicKeyBytes = null
            )


            val rowId = insertIgnore(toInsert)
            if (rowId != -1L) return UpsertResult.Inserted

            // Rare race: row inserted between read and insert.
            return upsertMergeSafe(incoming.copy(fingerprint = fp))
        }

        val hasIncomingOnion = incomingOnion.isNotEmpty()
        val hasIncomingPub = incomingPub.isNotEmpty()

        val onionChanged = hasIncomingOnion && incomingOnion != existing.onion
        val keyChanged = hasIncomingPub && !incomingPub.contentEquals(existing.publicKeyBytes)

        if (!onionChanged && !keyChanged) return UpsertResult.NoChange

        // UNVERIFIED: apply changes directly (TOFU refresh).
        if (existing.trustLevel != ContactEntity.TRUST_VERIFIED) {
            val updated = existing.copy(
                onion = if (hasIncomingOnion) incomingOnion else existing.onion,
                publicKeyBytes = if (hasIncomingPub) incomingPub else existing.publicKeyBytes,
                changeState = ContactEntity.CHANGE_NONE,
                pendingOnion = null,
                pendingPublicKeyBytes = null
                // keep displayName, keep trustLevel (still unverified)
            )
            update(updated)
            return UpsertResult.UpdatedUnverified
        }

        // VERIFIED: store pending changes for explicit approval.
        val newChangeState = when {
            keyChanged && onionChanged -> ContactEntity.CHANGE_BOTH
            keyChanged -> ContactEntity.CHANGE_KEY_CHANGED
            else -> ContactEntity.CHANGE_ONION_CHANGED
        }

        val updated = existing.copy(
            pendingOnion = if (onionChanged) incomingOnion else existing.pendingOnion,
            pendingPublicKeyBytes = if (keyChanged) incomingPub else existing.pendingPublicKeyBytes,
            changeState = newChangeState
        )

        update(updated)
        return UpsertResult.PendingApproval(keyChanged = keyChanged, onionChanged = onionChanged)
    }

    /**
     * Approve pending identity change:
     * - Applies pending values to pinned onion/publicKeyBytes if present,
     * - Clears pending fields,
     * 
     * displayName must be preserved.
     */
    @Transaction
    fun approvePending(fp: String) {
        val normFp = fp.trim().uppercase()
        val existing = getByFingerprint(normFp) ?: return

        val pendingOnion = existing.pendingOnion?.trim()
        val pendingPub = existing.pendingPublicKeyBytes

        val applied = existing.copy(
            onion = if (!pendingOnion.isNullOrEmpty()) pendingOnion else existing.onion,
            publicKeyBytes = if (pendingPub != null && pendingPub.isNotEmpty()) pendingPub else existing.publicKeyBytes,
            pendingOnion = null,
            pendingPublicKeyBytes = null,
            trustLevel = existing.trustLevel,
            changeState = ContactEntity.CHANGE_NONE
        )


        update(applied)
    }

    /**
     * Reject pending identity change:
     * - Clears pending fields,
     * - Sets changeState to NONE,
     * - Leaves trustLevel unchanged.
     *
     * displayName must be preserved.
     */
    @Transaction
    fun rejectPending(fp: String) {
        val normFp = fp.trim().uppercase()
        val existing = getByFingerprint(normFp) ?: return

        val cleared = existing.copy(
            pendingOnion = null,
            pendingPublicKeyBytes = null,
            changeState = ContactEntity.CHANGE_NONE
        )

        update(cleared)
    }

    /**
     * Apply an inbound onion update for an existing contact.
     *
     * Policy:
     * - UNVERIFIED: update onion directly (TOFU refresh), clear pending fields.
     * - VERIFIED: never overwrite onion silently; store pendingOnion and mark changeState.
     *
     * Returns true if applied/stored, false if contact does not exist.
     */
    @Transaction
    fun applyInboundOnionUpdate(senderFp: String, newOnionRaw: String): Boolean {
        val fp = senderFp.trim().uppercase()
        val existing = getByFingerprint(fp) ?: return false

        val newOnion = newOnionRaw.trim()
        if (newOnion.isEmpty()) return false

        // No change.
        if (newOnion == existing.onion) return true

        // UNVERIFIED: TOFU refresh.
        if (existing.trustLevel != ContactEntity.TRUST_VERIFIED) {
            val updated = existing.copy(
                onion = newOnion,
                pendingOnion = null,
                pendingPublicKeyBytes = null,
                changeState = ContactEntity.CHANGE_NONE
            )
            update(updated)
            return true
        }

        // VERIFIED: store pending onion. Preserve any existing pending key state.
        val newChangeState = when (existing.changeState) {
            ContactEntity.CHANGE_KEY_CHANGED,
            ContactEntity.CHANGE_BOTH -> ContactEntity.CHANGE_BOTH
            else -> ContactEntity.CHANGE_ONION_CHANGED
        }

        val updated = existing.copy(
            pendingOnion = newOnion,
            changeState = newChangeState
        )
        update(updated)
        return true
    }
}
