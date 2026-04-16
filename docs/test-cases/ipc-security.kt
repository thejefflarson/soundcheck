// Test case: ipc-security (A01:2025)
// Android IPC surface with three distinct exported-component failures.
//
// Companion AndroidManifest.xml (for reference):
//   <activity android:name=".DeepLinkActivity" android:exported="true">
//       <intent-filter>
//           <action android:name="android.intent.action.VIEW"/>
//           <category android:name="android.intent.category.DEFAULT"/>
//           <category android:name="android.intent.category.BROWSABLE"/>
//           <data android:scheme="myapp"/>
//       </intent-filter>
//   </activity>
//   <receiver android:name=".SyncReceiver" android:exported="true"/>

package com.example.insecure

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle

// BUG: Exported Activity accepts VIEW intents from any caller and acts on the
// payload without checking the caller's package signature or requiring a
// signature-level permission. A malicious app on the device can trigger
// privileged in-app actions by sending a crafted intent.
class DeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data: Uri? = intent.data
        // BUG: Custom URL scheme handler dispatches on the raw intent URI with
        // no scheme/host allowlist. Any app registering a matching intent or
        // any webpage opening `myapp://transfer?to=...&amount=...` reaches the
        // privileged handler directly.
        if (data != null) {
            val action = data.getQueryParameter("action") ?: "open"
            val target = data.getQueryParameter("to") ?: ""
            handlePrivilegedAction(action, target)
        }
        finish()
    }

    private fun handlePrivilegedAction(action: String, target: String) {
        // performs account-sensitive work
    }
}

// BUG: BroadcastReceiver is exported (see manifest) with no android:permission
// attribute, so any installed app can broadcast SYNC_NOW and force a token
// refresh / data sync on demand.
class SyncReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "com.example.insecure.SYNC_NOW") {
            val userId = intent.getStringExtra("user_id") ?: return
            triggerBackgroundSync(context, userId)
        }
    }

    private fun triggerBackgroundSync(context: Context, userId: String) {
        // kicks off authenticated network sync for userId
    }
}
