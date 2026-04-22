package com.example.smscompanion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.telephony.SmsMessage
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class SmsReceiver : BroadcastReceiver() {

    private val client = OkHttpClient()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()
    private val channelId = "sms_channel"

    override fun onReceive(context: Context, intent: Intent) {
        Log.d("SmsReceiver", "onReceive triggered with action: ${intent.action}")
        
        val action = intent.action
        if (action == "android.provider.Telephony.SMS_RECEIVED" || 
            action == "android.provider.Telephony.SMS_DELIVER" ||
            action == "android.intent.action.DATA_SMS_RECEIVED" ||
            action == "com.example.smscompanion.SIMULATE_SMS") {
            
            val pendingResult = goAsync()
            
            try {
                if (action == "com.example.smscompanion.SIMULATE_SMS") {
                    val sender = intent.getStringExtra("sender") ?: "Simulated-Sender"
                    val messageBody = intent.getStringExtra("message") ?: "Simulated message body"
                    handleIncomingSms(context, sender, messageBody, "Simulated", pendingResult)
                    return
                }

                val messages = android.provider.Telephony.Sms.Intents.getMessagesFromIntent(intent)

                if (messages != null && messages.isNotEmpty()) {
                    for (smsMessage in messages) {
                        val sender = smsMessage.displayOriginatingAddress ?: "Unknown"
                        val messageBody = smsMessage.messageBody ?: ""

                        Log.d("SmsReceiver", "Received SMS from $sender: $messageBody")
                        handleIncomingSms(context, sender, messageBody, "Received", pendingResult)
                    }
                } else {
                    // Fallback for older method or unexpected intent structure
                    val bundle = intent.extras
                    val pdus = bundle?.get("pdus") as? Array<*>
                    val format = bundle?.getString("format")
                    pdus?.forEach { pdu ->
                        val message = SmsMessage.createFromPdu(pdu as ByteArray, format)
                        val sender = message.displayOriginatingAddress ?: "Unknown"
                        val body = message.messageBody ?: ""
                        handleIncomingSms(context, sender, body, "Received (Alt)", pendingResult)
                    } ?: pendingResult.finish()
                }
            } catch (e: Exception) {
                Log.e("SmsReceiver", "Error parsing SMS: ${e.message}")
                notifyMainActivity(context, "System", "Error parsing incoming SMS: ${e.message}", "Error")
                pendingResult.finish()
            }
        }
    }

    private fun handleIncomingSms(context: Context, sender: String, message: String, status: String, pendingResult: PendingResult? = null) {
        showNotification(context, sender, message)
        notifyMainActivity(context, sender, message, status)
        forwardSmsToServer(context, sender, message, pendingResult)
    }

    private fun showNotification(context: Context, sender: String, message: String) {
        val builder = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("SMS from $sender")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)

        try {
            with(NotificationManagerCompat.from(context)) {
                if (ActivityCompat.checkSelfPermission(context, android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                    notify(System.currentTimeMillis().toInt(), builder.build())
                }
            }
        } catch (e: Exception) {
            Log.e("SmsReceiver", "Notification error: ${e.message}")
        }
    }

    private fun suggestCorrection(url: String): String? {
        var processedUrl = url.trim()
        if (!processedUrl.startsWith("http")) {
            processedUrl = "http://$processedUrl"
        }
        
        val addressPart = processedUrl.substringAfter("://")
        
        // Match 4 octets separated by dots, followed by a dot and 4-5 digits (e.g. 192.168.1.1.5000)
        val regex = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{4,5})""")
        val match = regex.find(addressPart)
        
        if (match != null) {
            val ip = match.groupValues[1]
            val port = match.groupValues[2]
            val path = if (addressPart.contains("/")) "/" + addressPart.substringAfter("/", "") else "/api/sms"
            return "http://$ip:$port$path"
        }
        
        // Ensure /api/sms path exists if it's just an IP:PORT
        if (!processedUrl.contains("/api/")) {
            val base = processedUrl.trimEnd('/')
            return "$base/api/sms"
        }
        
        return if (processedUrl != url) processedUrl else null
    }

    private fun notifyMainActivity(context: Context, sender: String, message: String, status: String) {
        // 1. Send broadcast for live UI updates if app is open
        val intent = Intent("com.example.smscompanion.SMS_UPDATE")
        intent.putExtra("sender", sender)
        intent.putExtra("message", message)
        intent.putExtra("status", status)
        intent.setPackage(context.packageName)
        context.sendBroadcast(intent)

        // 2. Persist log directly to SharedPreferences so it's not lost if app is closed
        val prefs = context.getSharedPreferences("SmsPrefs", Context.MODE_PRIVATE)
        val currentLogs = prefs.getString("logs", "No activity yet...")
        val timeStamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        val newEntry = "$timeStamp: [$status] From $sender: $message"
        
        val updatedLogs = if (currentLogs == "No activity yet...") newEntry else "$newEntry\n$currentLogs"
        prefs.edit().putString("logs", updatedLogs.take(2000)).apply()
    }

    private fun forwardSmsToServer(context: Context, sender: String, message: String, pendingResult: PendingResult? = null) {
        val prefs = context.getSharedPreferences("SmsPrefs", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("server_url", "http://192.168.100.8:5000/api/sms") ?: ""

        // Apply auto-correction just in case it's still broken in storage
        val cleanUrl = suggestCorrection(serverUrl) ?: serverUrl

        val json = JSONObject()
        json.put("sender", sender)
        json.put("device", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        json.put("text", message)
        json.put("type", "sms")
        json.put("timestamp", System.currentTimeMillis())
        json.put("status", "forwarded")

        val body = json.toString().toRequestBody(jsonMediaType)
        val request = Request.Builder()
            .url(cleanUrl)
            .post(body)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                val errorMsg = when {
                    e.message?.contains("cleartest", ignoreCase = true) == true -> "Cleartext blocked"
                    e.message?.contains("connection refused", ignoreCase = true) == true -> "Refused"
                    e.message?.contains("timed out", ignoreCase = true) == true -> "Timeout"
                    else -> e.message?.take(15) ?: "Error"
                }
                Log.e("SmsReceiver", "Failed to send SMS to server: ${e.message}")
                notifyMainActivity(context, sender, message, "Fail: $errorMsg")
                try {
                    pendingResult?.finish()
                } catch (e: Exception) {
                    // Already finished or error
                }
            }

            override fun onResponse(call: Call, response: Response) {
                Log.d("SmsReceiver", "Successfully sent SMS to server. Code: ${response.code}")
                notifyMainActivity(context, sender, message, "Forwarded (Code ${response.code})")
                response.close()
                try {
                    pendingResult?.finish()
                } catch (e: Exception) {
                    // Already finished or error
                }
            }
        })
    }

}
