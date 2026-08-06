package dev.vroot.checker.probes

import android.provider.Settings
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/** Настройки разработчика, ADB и мок-локация. */
class AdbSettingsProbe : BaseProbe() {
    override val id = "debug.adb"
    override val displayName = "Режим разработчика и ADB"
    override val category = Category.DEV_SETTINGS

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val cr = ctx.app.contentResolver

        fun global(key: String): Int = runCatching { Settings.Global.getInt(cr, key, 0) }.getOrDefault(0)

        val adb = global(Settings.Global.ADB_ENABLED)
        out += signal(
            id = "adb_enabled",
            title = "Отладка по USB включена",
            triggered = adb == 1,
            severity = Severity.MEDIUM,
            confidence = 95,
            why = "С включённым ADB любой, кто получит доступ к устройству, может залить frida-server или вытащить данные приложений.",
            method = "Settings.Global",
            evidence = listOf(ev("adb_enabled", adb)),
        )

        val dev = global(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
        out += signal(
            id = "dev_settings",
            title = "Меню разработчика активно",
            triggered = dev == 1,
            severity = Severity.LOW,
            confidence = 90,
            why = "Само по себе не угроза, но это предварительное условие для ADB, мок-локации и отладки приложений.",
            method = "Settings.Global",
            evidence = listOf(ev("development_settings_enabled", dev)),
        )

        val mock = runCatching {
            Settings.Secure.getString(cr, Settings.Secure.ALLOW_MOCK_LOCATION).orEmpty()
        }.getOrDefault("")
        out += signal(
            id = "mock_location",
            title = "Разрешены фиктивные локации",
            triggered = mock == "1",
            severity = Severity.LOW,
            confidence = 70,
            why = "Подмена GPS часто идёт в комплекте с клонами и эмуляторами для обхода геопроверок.",
            method = "Settings.Secure",
            evidence = listOf(ev("allow_mock_location", mock)),
        )

        val adbSecure = ctx.prop("ro.adb.secure")
        val secureProp = ctx.prop("ro.secure")
        out += signal(
            id = "adb_secure_prop",
            title = "Отключёна авторизация ADB",
            triggered = adbSecure == "0" || secureProp == "0",
            severity = Severity.HIGH,
            confidence = 85,
            why = "ro.adb.secure=0 или ro.secure=0 означают eng/userdebug-сборку: adb подключается без подтверждения и часто сразу как root.",
            method = "SystemProperties",
            evidence = listOf(ev("ro.adb.secure", adbSecure), ev("ro.secure", secureProp)),
        )

        val wifiAdb = ctx.prop("service.adb.tcp.port")
        out += signal(
            id = "adb_over_tcp",
            title = "ADB слушает по сети",
            triggered = wifiAdb.isNotEmpty() && wifiAdb != "0" && wifiAdb != "-1",
            severity = Severity.HIGH,
            confidence = 90,
            why = "Активный TCP-порт ADB открывает устройство для удалённого управления из локальной сети.",
            method = "SystemProperties",
            evidence = listOf(ev("service.adb.tcp.port", wifiAdb)),
        )

        return out
    }
}
