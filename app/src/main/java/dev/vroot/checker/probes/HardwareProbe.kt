package dev.vroot.checker.probes

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.camera2.CameraManager
import android.os.BatteryManager
import android.os.SystemClock
import android.telephony.TelephonyManager
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge
import java.net.NetworkInterface

/**
 * Circumstantial evidence of a virtual environment: sensors, cameras, battery,
 * network adapter, uptime and thermal zones.
 *
 * Every signal here is deliberately low or medium severity. None of them proves
 * anything on its own - a phone can legitimately have an odd sensor list - but
 * together they describe hardware that does not behave like hardware.
 */
class HardwareProbe : BaseProbe() {
    override val id = "virt.hardware"
    override val displayName = "Hardware and sensors"
    override val category = Category.HARDWARE
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val app = ctx.app

        val sensors = runCatching {
            (app.getSystemService(Context.SENSOR_SERVICE) as SensorManager).getSensorList(Sensor.TYPE_ALL)
        }.getOrNull().orEmpty()
        val fakeVendor = sensors.count {
            it.vendor.contains("goldfish", true) || it.vendor.contains("aosp", true) || it.vendor.contains("emulator", true)
        }
        out += signal(
            id = "sensors",
            title = "Implausible sensor inventory",
            triggered = sensors.size < 6 || fakeVendor > 0,
            severity = Severity.MEDIUM,
            confidence = if (fakeVendor > 0) 85 else 60,
            why = "A real phone exposes dozens of sensors from real vendors. Emulators return a short list attributed to AOSP or Goldfish.",
            method = "SensorManager",
            evidence = listOf(ev("count", sensors.size), ev("fake_vendor_sensors", fakeVendor)) +
                sensors.take(5).map { ev(it.name, it.vendor) },
        )

        val cameras = runCatching {
            (app.getSystemService(Context.CAMERA_SERVICE) as CameraManager).cameraIdList.size
        }.getOrDefault(-1)
        out += signal(
            id = "cameras",
            title = "No cameras at all",
            triggered = cameras == 0,
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Phones without a single camera barely exist, while many virtual machines and cloud phones have none.",
            method = "CameraManager",
            evidence = listOf(ev("camera_count", cameras)),
        )

        val battery = runCatching {
            app.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        }.getOrNull()
        val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val temp = battery?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
        val plugged = battery?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1
        out += signal(
            id = "battery",
            title = "Synthetic battery readings",
            triggered = (level == 100 && plugged > 0 && (temp <= 0 || temp == 250)) || temp == 0,
            severity = Severity.LOW,
            confidence = 60,
            why = "Emulators report fixed values: a permanent 100 percent, power always connected, and a temperature of exactly 25.0 C or 0.",
            method = "ACTION_BATTERY_CHANGED",
            evidence = listOf(ev("level", level), ev("temp_decikelvin", temp), ev("plugged", plugged)),
        )

        val tm = runCatching { app.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager }.getOrNull()
        val operator = runCatching { tm?.networkOperatorName.orEmpty() }.getOrDefault("")
        val simState = runCatching { tm?.simState ?: -1 }.getOrDefault(-1)
        out += signal(
            id = "telephony",
            title = "Telephony looks emulated",
            triggered = operator.equals("Android", true) || operator.equals("emulator", true),
            severity = Severity.HIGH,
            confidence = 90,
            why = "A network operator literally named Android is the hardcoded default of the AOSP emulator.",
            method = "TelephonyManager",
            evidence = listOf(ev("operator", operator), ev("sim_state", simState)),
        )

        val macs = runCatching {
            NetworkInterface.getNetworkInterfaces().toList().mapNotNull { nif ->
                nif.hardwareAddress?.joinToString(":") { b -> String.format("%02x", b) }?.let { nif.name to it }
            }
        }.getOrDefault(emptyList())
        val vmMac = macs.filter { (_, mac) ->
            mac.startsWith("08:00:27") || mac.startsWith("00:05:69") || mac.startsWith("00:0c:29") ||
                mac.startsWith("00:1c:14") || mac.startsWith("52:54:00") || mac == "02:00:00:00:00:00"
        }
        out += signal(
            id = "mac_oui",
            title = "MAC address from a virtualization range",
            triggered = vmMac.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 80,
            why = "The OUI prefixes 08:00:27 (VirtualBox), 00:0c:29 (VMware) and 52:54:00 (QEMU/KVM) give away a virtual network adapter.",
            method = "NetworkInterface",
            evidence = vmMac.map { ev(it.first, it.second) },
        )

        val uptimeMs = SystemClock.elapsedRealtime()
        out += signal(
            id = "uptime",
            title = "Suspiciously short uptime",
            triggered = uptimeMs < 90_000,
            severity = Severity.LOW,
            confidence = 50,
            why = "A freshly booted system is typical of disposable virtual machines and emulator farms where an image is spun up per task.",
            method = "SystemClock.elapsedRealtime",
            evidence = listOf(ev("uptime_ms", uptimeMs.toString())),
        )

        val thermal = NativeBridge.openDirCount("/sys/class/thermal")
        out += signal(
            id = "thermal_zones",
            title = "No thermal zones",
            triggered = thermal == 0,
            severity = Severity.LOW,
            confidence = 60,
            why = "A real SoC always exposes thermal sensors under /sys/class/thermal. An empty directory points at virtual hardware.",
            method = "jni: readdir",
            evidence = listOf(ev("thermal_zone_count", thermal)),
        )

        return out
    }
}
