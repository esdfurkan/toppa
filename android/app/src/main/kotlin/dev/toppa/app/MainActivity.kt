package dev.toppa.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat

/**
 * Dashboard (roadmap Step 5): start/stop the relay service, toggle the DNS
 * shield, and request the battery-optimization exemption. Transport
 * arbitration UI and pairing QR land with their own feature milestones.
 */
class MainActivity : ComponentActivity() {

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startService(Intent(this, ToppaVpnService::class.java).setAction(ToppaVpnService.ACTION_START))
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Dashboard() } }
    }

    @Composable
    private fun Dashboard() {
        val context = LocalContext.current
        var relayRunning by remember { mutableStateOf(false) }
        var shieldRunning by remember { mutableStateOf(false) }

        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Toppa", style = MaterialTheme.typography.headlineMedium)
            Text("Relay: ${if (relayRunning) "running" else "stopped"}")
            Text("DNS shield: ${if (shieldRunning) "on" else "off"}")
            Text(
                "USB is the default transport — connect the phone, enable USB debugging, and let the PC run `toppasvc`.",
                style = MaterialTheme.typography.bodySmall,
            )

            Button(onClick = {
                val action = if (relayRunning) RelayForegroundService.ACTION_STOP else RelayForegroundService.ACTION_START
                ContextCompat.startForegroundService(context, Intent(context, RelayForegroundService::class.java).setAction(action))
                relayRunning = !relayRunning
            }) {
                Text(if (relayRunning) "Stop relay" else "Start relay")
            }

            Button(onClick = {
                if (shieldRunning) {
                    startService(Intent(context, ToppaVpnService::class.java).setAction(ToppaVpnService.ACTION_STOP))
                    shieldRunning = false
                } else {
                    val consent = VpnService.prepare(context)
                    if (consent == null) {
                        startService(Intent(context, ToppaVpnService::class.java).setAction(ToppaVpnService.ACTION_START))
                        shieldRunning = true
                    } else {
                        vpnConsent.launch(consent)
                    }
                }
            }) {
                Text(if (shieldRunning) "Disable DNS shield" else "Enable DNS shield")
            }

            Button(onClick = {
                // Battery-optimization exemption (docs/ARCHITECTURE.md §2.4);
                // distribution is GitHub/F-Droid, so the Play policy
                // restriction on this intent does not apply to us.
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:$packageName"))
                context.startActivity(intent)
            }) {
                Text("Battery optimization exemption")
            }
        }
    }
}
