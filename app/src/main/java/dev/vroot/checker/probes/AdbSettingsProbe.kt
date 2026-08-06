package dev.vroot.checker.probes

import android.provider.Settings
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/** Developer options, ADB and mock locations. */
class AdbSettingsProbe : BaseProbe() {
    override val id = "debug.adb"
    override val displayName = "Developer mode and ADB"
    override val category = Category.DEBUG

    @Suppress("DEPRECATION")
    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val cr = ctx.app.contentResolver

        fun global(key: String): Int = runCatching { Settings.Global.getInt(cr, key, 0) }.getOrDefault(0)

        val adb = global(Settings.Global.ADB_ENABLED)
        out += signal(
            id = "adb_enabled",
            title = "USB debugging is enabled",
            triggered = adb == 1,
            // Deliberately LOW. This is a user setting, not a sign of tampering:
            // plenty of untouched retail phones have it on. Weighting it higher
            // made stock devices read as suspicious for no good reason.
            severity = Severity.LOW,
            confidence = 95,
            why = "With ADB on, anyone with access to the device can push frida-server or pull application data. " +
                "It is a user setting rather than evidence of tampering, so it only adds context here.",
            method = "Settings.Global",
            evidence = listOf(ev("adb_enabled", adb)),
        )

        val dev = global(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
        out += signal(
            id = "dev_settings",
            title = "Developer options are active",
            triggered = dev == 1,
            // Informational only: it is a precondition for other findings, never
            // a finding of its own.
            severity = Severity.INFO,
            confidence = 90,
            why = "Not a threat in itself, but a precondition for ADB, mock locations and app debugging.",
            method = "Settings.Global",
            evidence = listOf(ev("development_settings_enabled", dev)),
        )

        val mock = runCatching {
            Settings.Secure.getString(cr, Settings.Secure.ALLOW_MOCK_LOCATION).orEmpty()
        }.getOrDefault("")
        out += signal(
            id = "mock_location",
            title = "Mock locations are allowed",
            triggered = mock == "1",
            severity = Severity.LOW,
            confidence = 70,
            why = "GPS spoofing usually ships alongside clones and emulators used to defeat geo checks.",
            method = "Settings.Secure",
            evidence = listOf(ev("allow_mock_location", mock)),
        )

        val adbSecure = ctx.prop("ro.adb.secure")
        val secureProp = ctx.prop("ro.secure")
        out += signal(
            id = "adb_secure_prop",
            title = "ADB authorisation is disabled",
            triggered = adbSecure == "0" || secureProp == "0",
            severity = Severity.HIGH,
            confidence = 85,
            why = "ro.adb.secure=0 or ro.secure=0 means an eng/userdebug build: adb connects without confirmation, " +
                "often straight to a root shell.",
            method = "SystemProperties",
            evidence = listOf(ev("ro.adb.secure", adbSecure), ev("ro.secure", secureProp)),
        )

        val wifiAdb = ctx.prop("service.adb.tcp.port")
        out += signal(
            id = "adb_over_tcp",
            title = "ADB is listening on the network",
            triggered = wifiAdb.isNotEmpty() && wifiAdb != "0" && wifiAdb != "-1",
            severity = Severity.HIGH,
            confidence = 90,
            why = "An active ADB TCP port exposes the device to remote control from the local network.",
            method = "SystemProperties",
            evidence = listOf(ev("service.adb.tcp.port", wifiAdb)),
        )

        return out
    }
}
