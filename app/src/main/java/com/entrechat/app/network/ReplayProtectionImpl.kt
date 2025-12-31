/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import com.entrechat.app.config.LimitsConfig
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap

/**
 * v1 anti-replay implementation.
 *
 * Stores a bounded LRU set of recent nonces per sender fingerprint.
 *
 * Security properties:
 * - Thread-safe.
 * - Atomic check-and-mark to prevent double-accept under concurrent requests.
 *
 * Limitations:
 * - No TTL in v1 (LRU window only).
 * - No persistence (process restart clears the cache).
 */
class ReplayProtectionImpl : ReplayProtection {

    private class NonceLru(private val maxSize: Int) {
        private val map = object : LinkedHashMap<String, Boolean>(maxSize, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?): Boolean {
                return size > maxSize
            }
        }

        /**
         * Atomically checks presence and records if absent.
         *
         * @return true if newly inserted, false if already present.
         */
        @Synchronized
        fun putIfAbsent(nonce: String): Boolean {
            if (map.containsKey(nonce)) return false
            map[nonce] = true
            return true
        }
    }

    private val bySender = ConcurrentHashMap<String, NonceLru>()

    override fun markIfNew(senderFingerprint: String, nonce: String): Boolean {
        val sender = senderFingerprint.trim().uppercase()
        if (sender.isEmpty()) return false

        // Defense in depth: bound nonce size even if the caller already validated it.
        if (nonce.isEmpty() || nonce.length > LimitsConfig.MAX_NONCE_CHARS) return false

        val lru = bySender.getOrPut(sender) { NonceLru(LimitsConfig.MAX_NONCES_PER_CONTACT) }
        return lru.putIfAbsent(nonce)
    }
}
