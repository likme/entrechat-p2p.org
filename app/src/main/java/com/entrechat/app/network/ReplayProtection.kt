/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

/**
 * In-memory anti-replay protection.
 *
 * Contract:
 * - A message is uniquely identified for replay purposes by (senderFingerprint, nonce).
 * - The implementation must provide an atomic check-and-mark operation to avoid race conditions.
 *
 * v1 notes:
 * - No persistence (replays across process restarts are not detected).
 * - Bounded memory usage is required.
 */
interface ReplayProtection {

    /**
     * Atomically marks (senderFingerprint, nonce) as seen if it was not seen before.
     *
     * @return true if the nonce was new and has been recorded, false if it was already present (replay).
     */
    fun markIfNew(senderFingerprint: String, nonce: String): Boolean
}
