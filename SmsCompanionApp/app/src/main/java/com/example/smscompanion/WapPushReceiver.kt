package com.example.smscompanion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class WapPushReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Log.d("WapPushReceiver", "WAP Push received: ${intent.action}")
    }
}
