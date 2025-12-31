/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.contacts

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.entrechat.app.databinding.ItemContactBinding

class ContactsAdapter(
    private val onClick: (ContactRow) -> Unit,
    private val onLongClick: (ContactRow) -> Unit
) : ListAdapter<ContactRow, ContactsAdapter.VH>(DIFF) {

    class VH(val b: ItemContactBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemContactBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = getItem(position)

        holder.b.txtTitle.text = item.fingerprintShort

        holder.b.txtSubtitle.text = if (item.isNoteToSelf) {
            "Encrypted local notes"
        } else {
            val onionText = if (item.onion.isBlank()) {
                "(address not set)"
            } else {
                item.onionMasked
            }
            "$onionText  •  ${item.statusLabel}"
        }

        holder.b.root.setOnClickListener { onClick(item) }

        holder.b.root.setOnLongClickListener {
            if (item.isNoteToSelf) {
                false
            } else {
                onLongClick(item)
                true
            }
        }
    }

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<ContactRow>() {
            override fun areItemsTheSame(oldItem: ContactRow, newItem: ContactRow): Boolean {
                return oldItem.fingerprint == newItem.fingerprint &&
                    oldItem.isNoteToSelf == newItem.isNoteToSelf
            }

            override fun areContentsTheSame(oldItem: ContactRow, newItem: ContactRow): Boolean =
                oldItem == newItem
        }
    }
}
