/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.entrechat.app.databinding.ActivityMainMenuBinding
import com.entrechat.app.ui.contacts.ContactsActivity
import com.entrechat.app.ui.identity.IdentityActivity
import com.entrechat.app.ui.options.OptionsActivity

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainMenuBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        b = ActivityMainMenuBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.btnIdentity.setOnClickListener {
            startActivity(Intent(this, IdentityActivity::class.java))
        }
        b.btnContacts.setOnClickListener {
            startActivity(Intent(this, ContactsActivity::class.java))
        }
        b.btnOptions.setOnClickListener {
            startActivity(Intent(this, OptionsActivity::class.java))
        }
    }
}
