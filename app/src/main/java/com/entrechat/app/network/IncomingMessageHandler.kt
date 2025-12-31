/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.network

import org.json.JSONObject

interface IncomingMessageHandler {
    fun handleIncoming(envelope: JSONObject): IncomingMessageResult
}
