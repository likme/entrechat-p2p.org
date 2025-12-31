/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.common

object FpFormat {

    fun canonical(fp: String): String = fp.trim().uppercase()

    fun short(fp: String, keep: Int = 4): String {
        val x = canonical(fp)
        if (x.length <= keep * 2) return x
        return x.substring(0, keep) + "…" + x.substring(x.length - keep)
    }
}
