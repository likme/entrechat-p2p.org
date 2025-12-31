/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.crypto

interface DbPassphraseProvider {
    /**
     * Returns SQLCipher passphrase bytes. Caller should not log it.
     */
    fun getPassphrase(): ByteArray
}
