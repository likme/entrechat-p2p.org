/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.common

data class Ec2Invite(
    val inviteOnion: String,
    val token: String
)

object Ec2QrCodec {

    private val HOST_PORT_RE = Regex("^([^:]+)(?::(\\d{1,5}))?$")

    fun encode(inviteOnion: String, token: String): String {
        val o = inviteOnion.trim().lowercase()
        val t = token.trim()
        require(Ec2QrCodec.isValidOnionV3HostPort(o)) { "EC2_BAD_ONION" }
        require(Ec2QrCodec.isValidToken(t)) { "EC2_BAD_TOKEN" }

        return "ec2|$o|$t"
    }

    fun decode(text: String): Ec2Invite? {
        val s = text.trim()
        val parts = s.split("|")
        if (parts.size != 3) return null
        if (!parts[0].equals("ec2", ignoreCase = true)) return null

        val onion = parts[1].trim().lowercase()
        val token = parts[2].trim()

        if (!Ec2QrCodec.isValidOnionV3HostPort(onion)) return null
        if (!Ec2QrCodec.isValidToken(token)) return null


        return Ec2Invite(onion, token)
    }

    internal fun isValidToken(token: String): Boolean {
        if (token.length < 22 || token.length > 128) return false
        for (c in token) {
            val ok =
                (c in 'A'..'Z') ||
                    (c in 'a'..'z') ||
                    (c in '0'..'9') ||
                    c == '-' ||
                    c == '_'
            if (!ok) return false
        }
        return true
    }

    private fun isValidOnionV3HostPort(onion: String): Boolean {
        val t = onion.trim()
        if (t.isBlank()) return false
        if (t.startsWith("http://", true) || t.startsWith("https://", true)) return false
        if (t.contains("/") || t.contains("?") || t.contains("#")) return false

        val m = HOST_PORT_RE.matchEntire(t) ?: return false
        val host = m.groupValues[1].trim().lowercase()
        val portStr = m.groupValues.getOrNull(2)?.trim().orEmpty()

        if (!isValidOnionV3HostOnly(host)) return false
        if (portStr.isNotBlank()) {
            val p = portStr.toIntOrNull() ?: return false
            if (p !in 1..65535) return false
        }
        return true
    }

    private fun isValidOnionV3HostOnly(host: String): Boolean {
        val h = host.trim().lowercase()
        if (!h.endsWith(".onion")) return false
        val core = h.removeSuffix(".onion")
        if (core.length != 56) return false
        for (c in core) {
            val ok = (c in 'a'..'z') || (c in '2'..'7')
            if (!ok) return false
        }
        return true
    }
}
