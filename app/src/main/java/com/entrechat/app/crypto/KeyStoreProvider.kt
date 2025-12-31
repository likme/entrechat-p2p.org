/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

interface KeyStoreProvider {

    /**
     * Returns a single public key (typically encryption subkey).
     * Used for encryption only.
     */
    fun getPublicKeyForFingerprint(fingerprint: String): PgpPublicKey?

    /**
     * Returns the full OpenPGP public keyring bytes for a contact.
     * REQUIRED for signature verification (supports signing subkeys).
     */
    fun getPublicKeyRingBytesForFingerprint(fingerprint: String): ByteArray?

    /**
     * For decrypting incoming messages (recipient side).
     */
    fun getDecryptionPrivateKeyForFingerprint(fingerprint: String): PgpPrivateKey?

    /**
     * For signing outgoing messages (sender side).
     */
    fun getSigningPrivateKeyForFingerprint(fingerprint: String): PgpPrivateKey?
}
