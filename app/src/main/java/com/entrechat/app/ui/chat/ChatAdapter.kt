/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app.ui.chat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Toast
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.entrechat.app.databinding.ItemMsgInBinding
import com.entrechat.app.databinding.ItemMsgOutBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ChatAdapter :
    ListAdapter<ChatRow, RecyclerView.ViewHolder>(DIFF) {

    companion object {
        private const val VIEW_TYPE_IN = 1
        private const val VIEW_TYPE_OUT = 2

        private val DIFF = object : DiffUtil.ItemCallback<ChatRow>() {
            override fun areItemsTheSame(oldItem: ChatRow, newItem: ChatRow): Boolean =
                oldItem.msgId == newItem.msgId

            override fun areContentsTheSame(oldItem: ChatRow, newItem: ChatRow): Boolean =
                oldItem == newItem
        }

        private val TIME_FORMAT =
            SimpleDateFormat("HH:mm", Locale.getDefault())

        private fun statusLabel(raw: String): String = when (raw) {
            "QUEUED" -> "Queued"
            "SENT_HTTP_OK" -> "Sent"
            "FAILED" -> "Not sent"
            "RECEIVED" -> "Received"
            else -> raw
        }

        private fun metaText(row: ChatRow): String {
            val time = try {
                TIME_FORMAT.format(Date(row.createdAt))
            } catch (_: Throwable) {
                "--:--"
            }
            return "$time · ${statusLabel(row.status)}"
        }

        private fun copyToClipboard(ctx: Context, label: String, text: String) {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText(label, text))
        }
    }

    init {
        setHasStableIds(true)
    }

    override fun getItemId(position: Int): Long {
        val id = getItem(position).msgId ?: return RecyclerView.NO_ID
        return id.hashCode().toLong()
    }

    override fun getItemViewType(position: Int): Int =
        if (getItem(position).direction == "IN") VIEW_TYPE_IN else VIEW_TYPE_OUT

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        return if (viewType == VIEW_TYPE_IN) {
            val binding = ItemMsgInBinding.inflate(
                LayoutInflater.from(parent.context),
                parent,
                false
            )
            InViewHolder(binding)
        } else {
            val binding = ItemMsgOutBinding.inflate(
                LayoutInflater.from(parent.context),
                parent,
                false
            )
            OutViewHolder(binding)
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val row = getItem(position)
        when (holder) {
            is InViewHolder -> holder.bind(row)
            is OutViewHolder -> holder.bind(row)
        }
    }

    class InViewHolder(private val binding: ItemMsgInBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(row: ChatRow) {
            binding.txtBody.text = row.bodyPreview
            binding.txtMeta.text = metaText(row)

            // Long-press copies the displayed text. No logs.
            binding.txtBody.setOnLongClickListener {
                val v = row.bodyPreview?.toString().orEmpty().trim()
                if (v.isNotBlank()) {
                    copyToClipboard(binding.root.context, "Entrechat message", v)
                    Toast.makeText(binding.root.context, "Copied", Toast.LENGTH_SHORT).show()
                }
                true
            }
        }
    }

    class OutViewHolder(private val binding: ItemMsgOutBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(row: ChatRow) {
            binding.txtBody.text = row.bodyPreview
            binding.txtMeta.text = metaText(row)

            // Long-press copies the displayed text. No logs.
            binding.txtBody.setOnLongClickListener {
                val v = row.bodyPreview?.toString().orEmpty().trim()
                if (v.isNotBlank()) {
                    copyToClipboard(binding.root.context, "Entrechat message", v)
                    Toast.makeText(binding.root.context, "Copied", Toast.LENGTH_SHORT).show()
                }
                true
            }
        }
    }
}
