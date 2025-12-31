/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.config

import java.util.concurrent.TimeUnit

object RetryPolicy {

    val BASE_DELAY_MS: Long = TimeUnit.SECONDS.toMillis(2)
    val MAX_DELAY_MS: Long = TimeUnit.MINUTES.toMillis(15)

    const val MAX_ATTEMPTS: Int = 30
}
