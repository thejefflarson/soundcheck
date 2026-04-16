// Test case: insecure-local-storage (A02:2025)
// Android credential storage with three distinct cleartext failures.

package com.example.insecure

import android.content.Context
import android.webkit.CookieManager
import android.webkit.WebView
import java.io.File

class CredentialStore(private val context: Context) {

    // BUG: Auth token written to standard SharedPreferences in plaintext.
    // SharedPreferences XML lives in /data/data/<pkg>/shared_prefs/ and is
    // readable from device backups and on rooted devices. Use
    // EncryptedSharedPreferences with a MasterKey instead.
    fun saveAuthToken(token: String) {
        val prefs = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
        prefs.edit().putString("auth_token", token).apply()
    }

    // BUG: Username/password cached as cleartext in an unencrypted file under
    // filesDir. Any ADB backup or filesystem-access exploit trivially recovers
    // the credentials. Secrets should live in the Android Keystore / be
    // wrapped by EncryptedFile.
    fun cacheCredentials(username: String, password: String) {
        val cacheFile = File(context.filesDir, "creds.txt")
        cacheFile.writeText("$username:$password")
    }

    // BUG: Cleartext credential pushed into the WebView cookie store. The
    // cookie is persisted to WebView's on-disk cookie database with no
    // encryption, is exported in backups, and is visible to any WebView loaded
    // for the same host. Never stash raw credentials in cookies — use a
    // server-issued session token bound to Secure/HttpOnly + device keystore.
    fun seedWebViewSession(webView: WebView, username: String, password: String) {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setCookie(
            "https://api.example.com",
            "credentials=$username:$password; Path=/"
        )
        webView.loadUrl("https://api.example.com/dashboard")
    }
}
