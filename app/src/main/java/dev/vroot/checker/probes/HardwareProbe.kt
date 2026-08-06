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

/** Косвенные признаки виртуальной среды: сенсоры, камеры, батарея, сеть, uptime. */
class HardwareProbe : BaseProbe() {
    override val id = "virt.hardware"
    override val displayName = "Железо и сенсоры"
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
            title = "Набор сенсоров неправдоподобен",
            triggered = sensors.size < 6 || fakeVendor > 0,
            severity = Severity.MEDIUM,
            confidence = if (fakeVendor > 0) 85 else 60,
            why = "У реального телефона десятки сенсоров от реальных вендоров. Эмуляторы отдают короткий список с вендором AOSP/Goldfish.",
            method = "SensorManager",
            evidence = listOf(ev("count", sensors.size), ev("fake_vendor_sensors", fakeVendor)) +
                sensors.take(5).map { ev(it.name, it.vendor) },
        )

        val cameras = runCatching {
            (app.getSystemService(Context.CAMERA_SERVICE) as CameraManager).cameraIdList.size
        }.getOrDefault(-1)
        out += signal(
            id = "cameras",
            title = "Камеры отсутствуют",
            triggered = cameras == 0,
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Телефонов без единой камеры практически не бывает, а у части виртуалок и облачных телефонов камер нет вообще.",
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
            title = "Показания батареи синтетичны",
            triggered = (level == 100 && plugged > 0 && (temp <= 0 || temp == 250)) || temp == 0,
            severity = Severity.LOW,
            confidence = 60,
            why = "Эмуляторы отдают фиксированные значения: вечные 100%, подключённое питание и температуру 25.0 °C или 0.",
            method = "ACTION_BATTERY_CHANGED",
            evidence = listOf(ev("level", level), ev("temp_decikelvin", temp), ev("plugged", plugged)),
        )

        val tm = runCatching { app.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager }.getOrNull()
        val operator = runCatching { tm?.networkOperatorName.orEmpty() }.getOrDefault("")
        val simState = runCatching { tm?.simState ?: -1 }.getOrDefault(-1)
        out += signal(
            id = "telephony",
            title = "Телефония выглядит эмулированной",
            triggered = operator.equals("Android", true) || operator.equals("emulator", true),
            severity = Severity.HIGH,
            confidence = 90,
            why = "Оператор с именем «Android» — зашитый дефолт эмулятора AOSP.",
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
            title = "MAC-адрес из диапазона виртуализации",
            triggered = vmMac.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 80,
            why = "Префиксы OUI 08:00:27 (VirtualBox), 00:0c:29 (VMware), 52:54:00 (QEMU/KVM) выдают виртуальный сетевой адаптер.",
            method = "NetworkInterface",
            evidence = vmMac.map { ev(it.first, it.second) },
        )

        val uptimeMs = SystemClock.elapsedRealtime()
        out += signal(
            id = "uptime",
            title = "Подозрительно малый uptime",
            triggered = uptimeMs < 90_000,
            severity = Severity.LOW,
            confidence = 50,
            why = "Свежезагруженная система типична для одноразовых виртуалок и ферм эмуляторов, где образ поднимается под задачу.",
            method = "SystemClock.elapsedRealtime",
            evidence = listOf(ev("uptime_ms", uptimeMs.toString())),
        )

        val thermal = dev.vroot.checker.core.util.NativeBridge.openDirCount("/sys/class/thermal")
        out += signal(
            id = "thermal_zones",
            title = "Нет термозон",
            triggered = thermal == 0,
            severity = Severity.LOW,
            confidence = 60,
            why = "У реального SoC всегда есть термодатчики в /sys/class/thermal. Пустой каталог — признак виртуального железа.",
            method = "jni: readdir",
            evidence = listOf(ev("thermal_zone_count", thermal)),
        )

        return out
    }
}
