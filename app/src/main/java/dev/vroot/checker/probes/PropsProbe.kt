package dev.vroot.checker.probes

import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Props

/** Системные свойства: режим сборки, verified boot и подмена через resetprop. */
class PropsProbe : BaseProbe() {
    override val id = "root.props"
    override val displayName = "Системные свойства и verified boot"
    override val category = Category.SYSTEM_PROPS
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val debuggable = ctx.prop("ro.debuggable")
        val secure = ctx.prop("ro.secure")
        out += signal(
            id = "insecure_build",
            title = "Небезопасная сборка (ro.debuggable / ro.secure)",
            triggered = debuggable == "1" || secure == "0",
            severity = Severity.HIGH,
            confidence = 90,
            why = "На розничной прошивке всегда ro.debuggable=0 и ro.secure=1. Иначе это eng/userdebug-сборка или подменённые свойства — adb root доступен.",
            method = "SystemProperties + __system_property_get",
            evidence = listOf(ev("ro.debuggable", debuggable), ev("ro.secure", secure)),
        )

        val tags = Build.TAGS.orEmpty()
        val type = Build.TYPE.orEmpty()
        out += signal(
            id = "test_keys",
            title = "Сборка подписана test-keys",
            triggered = tags.contains("test-keys") || type == "userdebug" || type == "eng",
            severity = Severity.MEDIUM,
            confidence = 85,
            why = "Официальные прошивки подписаны release-keys. test-keys означает кастомную или отладочную сборку.",
            method = "android.os.Build",
            evidence = listOf(ev("Build.TAGS", tags), ev("Build.TYPE", type)),
        )

        val vbState = ctx.prop("ro.boot.verifiedbootstate")
        val locked = ctx.prop("ro.boot.flash.locked")
        val verity = ctx.prop("ro.boot.veritymode")
        val bootloaderUnlocked = (vbState.isNotEmpty() && vbState != "green") ||
            locked == "0" || verity.equals("disabled", true)
        out += signal(
            id = "verified_boot",
            title = "Verified Boot не в состоянии green",
            triggered = bootloaderUnlocked,
            severity = Severity.HIGH,
            confidence = 88,
            why = "Оранжевый/жёлтый verified boot или выключенный dm-verity — это разблокированный загрузчик. Без него поставить стойкий root практически невозможно.",
            method = "SystemProperties (ro.boot.*)",
            evidence = listOf(
                ev("ro.boot.verifiedbootstate", vbState),
                ev("ro.boot.flash.locked", locked),
                ev("ro.boot.veritymode", verity),
            ),
        )

        val watched = listOf(
            "ro.debuggable", "ro.secure", "ro.build.tags", "ro.build.type",
            "ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.build.fingerprint",
        )
        val mismatched = watched.map { Props.multi(it, ctx.config.allowShell) }.filter { it.mismatch }
        out += signal(
            id = "resetprop_mismatch",
            title = "Значения свойств различаются между каналами",
            triggered = mismatched.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 92,
            why = "Одно и то же свойство читается по-разному через SystemProperties, нативный API и getprop. Так выглядит маскировка (resetprop / hook на свойства).",
            method = "cross-check reflect vs jni vs shell",
            evidence = mismatched.map { ev(it.key, it.describe()) },
        )

        val dangerous = mapOf(
            "service.adb.root" to "1",
            "ro.adb.secure" to "0",
            "persist.sys.root_access" to "3",
            "persist.service.adb.enable" to "1",
        ).filter { (k, v) -> ctx.prop(k) == v }
        out += signal(
            id = "dangerous_props",
            title = "Опасные значения свойств",
            triggered = dangerous.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 80,
            why = "Эти свойства явно разрешают root-доступ или небезопасный adb.",
            method = "SystemProperties",
            evidence = dangerous.map { ev(it.key, it.value) },
        )

        return out
    }
}
