package com.example.smscompanion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.TelephonyManager
import android.util.Log
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class CallReceiver : BroadcastReceiver() {

    private val client = OkHttpClient()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == TelephonyManager.ACTION_PHONE_STATE_CHANGED) {
            val state = intent.getStringExtra(TelephonyManager.EXTRA_STATE)
            val incomingNumber = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER) ?: "Unknown"
            
            Log.d("CallReceiver", "Phone state changed: $state, Number: $incomingNumber")
            
            if (state == TelephonyManager.EXTRA_STATE_RINGING) {
                notifyMainActivity(context, incomingNumber, "Incoming Call", "Ringing")
                forwardCallToServer(context, incomingNumber, "Incoming Call")
            } else if (state == TelephonyManager.EXTRA_STATE_OFFHOOK) {
                notifyMainActivity(context, incomingNumber, "Call Answered/Outbound", "Offhook")
            } else if (state == TelephonyManager.EXTRA_STATE_IDLE) {
                notifyMainActivity(context, incomingNumber, "Call Ended", "Idle")
            }
        }
    }

    private fun notifyMainActivity(context: Context, number: String, message: String, status: String) {
        val intent = Intent("com.example.smscompanion.SMS_UPDATE")
        intent.putExtra("sender", number)
        intent.putExtra("message", message)
        intent.putExtra("status", status)
        intent.setPackage(context.packageName)
        context.sendBroadcast(intent)
    }

    private fun forwardCallToServer(context: Context, number: String, type: String) {
        val prefs = context.getSharedPreferences("SmsPrefs", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("server_url", "http://192.168.100.8:5000/api/sms") ?: ""

        // Force fix the URL
        val cleanUrl = suggestCorrection(serverUrl) ?: serverUrl

        val json = JSONObject()
        json.put("sender", number)
        json.put("device", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        json.put("text", "Call activity detected: $type from $number")
        json.put("type", "call")
        json.put("timestamp", System.currentTimeMillis())

        val body = json.toString().toRequestBody(jsonMediaType)
        val request = Request.Builder()
            .url(cleanUrl)
            .post(body)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                Log.e("CallReceiver", "Failed to send call event to server: ${e.message}")
                notifyMainActivity(context, number, "Call Forward Failed: ${e.message}", "Error")
            }

            override fun onResponse(call: Call, response: Response) {
                Log.d("CallReceiver", "Successfully sent call event to server")
                notifyMainActivity(context, number, "Call Log Forwarded", "Success")
                response.close()
            }
        })
    }

    private fun suggestCorrection(url: String): String? {
        var processedUrl = url.trim()
        if (!processedUrl.startsWith("http")) {
            processedUrl = "http://$processedUrl"
        }
        val addressPart = processedUrl.substringAfter("://")
        val regex = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{4,5})""")
        val match = regex.find(addressPart)
        if (match != null) {
            val ip = match.groupValues[1]
            val port = match.groupValues[2]
            val path = if (addressPart.contains("/")) "/" + addressPart.substringAfter("/", "") else "/api/sms"
            return "http://$ip:$port$path"
        }
        if (!processedUrl.contains("/api/")) {
            val base = processedUrl.trimEnd('/')
            return "$base/api/sms"
        }
        return if (processedUrl != url) processedUrl else null
    }
}
