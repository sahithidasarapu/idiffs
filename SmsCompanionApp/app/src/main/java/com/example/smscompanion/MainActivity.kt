package com.example.smscompanion

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.role.RoleManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Telephony
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private val SMS_PERMISSION_CODE = 100
    private lateinit var logText: TextView
    private val client = OkHttpClient()
    private val JSON = "application/json; charset=utf-8".toMediaType()

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "SMS Alerts"
            val descriptionText = "Notifications for incoming SMS activity"
            val importance = NotificationManager.IMPORTANCE_DEFAULT
            val channel = NotificationChannel("sms_channel", name, importance).apply {
                description = descriptionText
            }
            val notificationManager: NotificationManager =
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun showNotification(sender: String, message: String) {
        val builder = NotificationCompat.Builder(this, "sms_channel")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("SMS from $sender")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)

        try {
            with(NotificationManagerCompat.from(this)) {
                if (ActivityCompat.checkSelfPermission(this@MainActivity, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                    notify(System.currentTimeMillis().toInt(), builder.build())
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ActivityCompat.requestPermissions(this@MainActivity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 101)
                }
            }
        } catch (e: Exception) {
            addLog("System: Notification error - ${e.message}")
        }
    }

    private val smsUpdateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val sender = intent?.getStringExtra("sender") ?: "Unknown"
            val message = intent?.getStringExtra("message") ?: ""
            val status = intent?.getStringExtra("status") ?: "Received"
            addLog("[$status] From $sender: $message")
            
            // Only show notification here if it's a simulation. 
            // Real SMS notifications are now handled by SmsReceiver.
            if (status == "Simulated") {
                showNotification(sender, message)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
    }

    private fun updateStatus() {
        val smsGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        val isDefault = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = getSystemService(RoleManager::class.java)
            roleManager.isRoleHeld(RoleManager.ROLE_SMS)
        } else {
            Telephony.Sms.getDefaultSmsPackage(this) == packageName
        }

        val status = StringBuilder("Status: ")
        if (!smsGranted) {
            status.append("SMS Permission Missing! ")
        } else if (!isDefault) {
            status.append("Listening (Not Default App) ")
        } else {
            status.append("Listening (Default App - Recommended) ")
        }
        
        findViewById<TextView>(R.id.statusText).text = status.toString()
        if (!smsGranted) {
            findViewById<TextView>(R.id.statusText).setTextColor(android.graphics.Color.RED)
        } else if (!isDefault) {
            findViewById<TextView>(R.id.statusText).setTextColor(android.graphics.Color.parseColor("#FFA500")) // Orange
        } else {
            findViewById<TextView>(R.id.statusText).setTextColor(android.graphics.Color.GREEN)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        createNotificationChannel()

        val serverUrlInput = findViewById<EditText>(R.id.serverUrlInput)
        val saveButton = findViewById<Button>(R.id.saveButton)
        val testButton = findViewById<Button>(R.id.testButton)
        val simulateButton = findViewById<Button>(R.id.simulateButton)
        val clearButton = findViewById<Button>(R.id.clearButton)
        val defaultAppButton = findViewById<Button>(R.id.defaultAppButton)
        val statusText = findViewById<TextView>(R.id.statusText)
        logText = findViewById(R.id.logText)

        // Load saved URL
        val prefs = getSharedPreferences("SmsPrefs", MODE_PRIVATE)
        var savedUrl = prefs.getString("server_url", "http://192.168.100.8:5000/api/sms") ?: ""
        
        // Migrate old IP to new IP if found
        if (savedUrl.contains("192.168.29.126")) {
            val oldUrl = savedUrl
            savedUrl = savedUrl.replace("192.168.29.126", "192.168.100.8")
            prefs.edit().putString("server_url", savedUrl).apply()
            addLog("System: Migrated old IP from $oldUrl to $savedUrl")
        }

        // Auto-fix malformed URL on startup
        val correction = suggestCorrection(savedUrl)
        if (correction != null && correction != savedUrl) {
            savedUrl = correction
            prefs.edit().putString("server_url", savedUrl).apply()
            addLog("System: Auto-fixed saved URL typo on startup")
        }
        serverUrlInput.setText(savedUrl)

        // Load saved logs
        val savedLogs = prefs.getString("logs", "No activity yet...")
        logText.text = savedLogs

        saveButton.setOnClickListener {
            var url = serverUrlInput.text.toString().trim()
            val correction = suggestCorrection(url)
            if (correction != null && correction != url) {
                url = correction
                serverUrlInput.setText(url)
                addLog("System: Auto-corrected URL to $url")
                Toast.makeText(this, "Auto-corrected URL typo!", Toast.LENGTH_SHORT).show()
            }

            if (isValidUrl(url)) {
                prefs.edit().putString("server_url", url).apply()
                Toast.makeText(this, "Server URL saved!", Toast.LENGTH_SHORT).show()
                addLog("System: Server URL updated to $url")
            } else {
                addLog("Error: Invalid URL format. Must start with http:// and have a valid IP:PORT")
                Toast.makeText(this, "Invalid URL format", Toast.LENGTH_SHORT).show()
            }
        }

        clearButton.setOnClickListener {
            prefs.edit().putString("logs", "No activity yet...").apply()
            logText.text = "No activity yet..."
            Toast.makeText(this, "Logs cleared", Toast.LENGTH_SHORT).show()
        }

        defaultAppButton.setOnClickListener {
            requestDefaultSmsRole()
        }

        simulateButton.setOnClickListener {
            addLog("System: Triggering internal SMS receiver simulation...")
            val intent = Intent("com.example.smscompanion.SIMULATE_SMS")
            intent.putExtra("sender", "+1-555-SIM-ACTUAL")
            intent.putExtra("message", "Triggering full receiver logic via custom broadcast!")
            intent.setPackage(packageName)
            sendBroadcast(intent)
        }

        testButton.setOnClickListener {
            val urlInput = serverUrlInput.text.toString().trim()
            val correctedUrl = suggestCorrection(urlInput) ?: urlInput
            if (correctedUrl != urlInput) {
                serverUrlInput.setText(correctedUrl)
                addLog("System: Corrected URL for test: $correctedUrl")
            }
            sendTestData(correctedUrl)
        }

        checkPermission()
        updateStatus()
        
        val filter = IntentFilter("com.example.smscompanion.SMS_UPDATE")
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(smsUpdateReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(smsUpdateReceiver, filter)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(smsUpdateReceiver)
    }

    private fun isValidUrl(url: String): Boolean {
        if (!url.startsWith("http://") && !url.startsWith("https://")) return false
        
        // Basic check for IP:PORT vs IP.PORT
        // If there are 4 dots and no colon after http://, it might be IP.PORT
        val addressPart = url.substringAfter("://")
        val dotCount = addressPart.count { it == '.' }
        val hasColon = addressPart.contains(':')
        
        if (dotCount >= 4 && !hasColon) return false
        
        return try {
            url.toHttpUrlOrNull() != null
        } catch (e: Exception) {
            false
        }
    }

    private fun suggestCorrection(url: String): String? {
        var processedUrl = url.trim()
        if (processedUrl.isEmpty()) return null
        
        if (!processedUrl.startsWith("http")) {
            processedUrl = "http://$processedUrl"
        }
        
        var addressPart = processedUrl.substringAfter("://")
        
        // 1. Fix the dot typo: 192.168.1.1.5000 -> 192.168.1.1:5000
        val dotTypoRegex = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{4,5})""")
        val match = dotTypoRegex.find(addressPart)
        if (match != null) {
            val ip = match.groupValues[1]
            val port = match.groupValues[2]
            val remaining = addressPart.substringAfter(match.value, "")
            addressPart = "$ip:$port$remaining"
        }
        
        // 2. Ensure it ends with /api/sms if no path is provided
        var finalUrl = "http://$addressPart"
        if (!finalUrl.contains("/api/")) {
            finalUrl = finalUrl.trimEnd('/') + "/api/sms"
        }
        
        return if (finalUrl != url) finalUrl else null
    }

    private fun addLog(message: String) {
        val timeStamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timeStamp: $message"

        runOnUiThread {
            val currentLog = logText.text.toString()
            val newLog = if (currentLog == "No activity yet...") {
                logEntry
            } else {
                "$logEntry\n$currentLog"
            }.take(2000)
            logText.text = newLog

            // Also persist logs added via MainActivity (like system/test logs)
            val prefs = getSharedPreferences("SmsPrefs", MODE_PRIVATE)
            prefs.edit().putString("logs", newLog).apply()
        }
    }

    private fun sendTestData(url: String) {
        if (url.isEmpty()) {
            Toast.makeText(this, "Please enter a URL first", Toast.LENGTH_SHORT).show()
            return
        }

        // Clean the URL one last time before sending
        val cleanUrl = suggestCorrection(url) ?: url
        addLog("System: Sending test request to $cleanUrl...")
        
        val json = JSONObject()
        json.put("sender", "TEST-SENDER")
        json.put("text", "This is a test message from SMS Companion App")
        json.put("type", "sms")
        json.put("device", Build.MODEL)
        json.put("timestamp", System.currentTimeMillis())

        val body = json.toString().toRequestBody(JSON)
        val request = Request.Builder()
            .url(cleanUrl)
            .post(body)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                val errorMsg = when {
                    e.message?.contains("cleartest", ignoreCase = true) == true -> "Cleartext blocked (Use HTTPs or fix manifest)"
                    e.message?.contains("connection refused", ignoreCase = true) == true -> "Connection Refused (Check if Server is running)"
                    e.message?.contains("timed out", ignoreCase = true) == true -> "Timed Out (Check Firewall/IP Address)"
                    else -> e.message ?: "Unknown Network Error"
                }
                addLog("Error: Test failed - $errorMsg")
                Log.e("MainActivity", "Test failed", e)
            }

            override fun onResponse(call: Call, response: Response) {
                if (response.isSuccessful) {
                    addLog("Success: Server accepted data! (Code ${response.code})")
                } else {
                    addLog("Error: Server rejected data with code ${response.code}")
                }
                response.close()
            }
        })
    }

    private fun requestDefaultSmsRole() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = getSystemService(RoleManager::class.java)
            if (roleManager.isRoleAvailable(RoleManager.ROLE_SMS)) {
                if (roleManager.isRoleHeld(RoleManager.ROLE_SMS)) {
                    Toast.makeText(this, "App is already the default SMS app", Toast.LENGTH_SHORT).show()
                } else {
                    val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_SMS)
                    startActivityForResult(intent, 123)
                }
            }
        } else {
            if (Telephony.Sms.getDefaultSmsPackage(this) != packageName) {
                val intent = Intent(Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT)
                intent.putExtra(Telephony.Sms.Intents.EXTRA_PACKAGE_NAME, packageName)
                startActivity(intent)
            } else {
                Toast.makeText(this, "App is already the default SMS app", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkPermission() {
        val permissions = mutableListOf(
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_CALL_LOG
        )
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        val neededPermissions = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (neededPermissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, neededPermissions.toTypedArray(), SMS_PERMISSION_CODE)
        } else {
            findViewById<TextView>(R.id.statusText).text = "Status: Listening for SMS..."
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == SMS_PERMISSION_CODE) {
            updateStatus()
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "SMS Permission Granted", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "SMS Permission Denied", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
