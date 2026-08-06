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
import java.net.NetworkInterface

/** Косвенные признаки: сенсоры, камеры, батарея, сеть, uptime. */
class HardwareProbe : BaseProbe() {
    override val id = "virt.hardware"
    override val displayName = "Железо и сенсоры"
    override val category = Category.HARDWARE
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val app = ctx.app

        val sensors = runCatching {
            (app.getSystemService(Context.SENSOR_SERVICE) as SensorManager)
                .getSensorList(Sensor.TYPE_ALL)
        }.getOrNull().orEmpty()
        val vendorFake = sensors.count { it.vendor.contains("goldfish", true) || it.vendor.contains("aosp", true) }
        out += signal(
            id = "sensors",
            title = "Набор сенсоров неправдоподобен",
            triggered = sensors.size < 6 || vendorFake > 0,
            severity = Severity.MEDIUM,
            confidence = if (vendorFake > 0) 85 else 60,
            why = "У реального телефона десятки сенсоров от реальных вендоров. Эмуляторы отдают маленький список с вендором AOSP/Goldfish.",
            method = "SensorManager",
            evidence = listOf(ev("count", sensors.size), ev("fake_vendor", vendorFake)) +
                sensors.take(5).map { ev(it.name, it.vendor) },
        )

        val cameras = runCatching {
            (app.getSystemService(Context.CAMERA_SERVICE) as CameraManager).cameraIdList.size
        }.getOrDefault(-1)
        out += signal(
            id = "cameras",
            title = "Камер