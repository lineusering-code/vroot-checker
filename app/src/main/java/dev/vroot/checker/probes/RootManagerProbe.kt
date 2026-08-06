package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** Magisk / Zygisk / KernelSU / APatch и их следы в ФС, сокетах и памяти. */
class RootManagerProbe : BaseProbe() {
    override val id = "root.manager"
    override val displayName = "Root-менеджеры (Magisk / KernelSU / APatch)"
    override val category = Category.ROOT_MANAGER
    override val timeoutMs = 2000L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val magisk = Sys.probeAll(Signatures.MAGISK_PATHS).filter { it.exists }
        out += signal(
            id = "magisk_files",
            title = "Артефакты Magisk в файловой системе",
            triggered = magisk.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Каталоги /data/adb/magisk, /data/adb/modules и /sbin/.magisk создаёт только Magisk. DenyList скрывает монтирования, но часто оставляет сами каталоги читаемыми.",
            method = "java.io.File + faccessat(JNI)",
            evidence = magisk.map { ev(it.path, it.describe()) },
        )

        val ksu = Sys.probeAll(Signatures.KERNELSU_PATHS).filter { it.exists }
        out += signal(
            id = "kernelsu_apatch",
            title = "Следы KernelSU / APatch",
            triggered = ksu.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 92,
            why = "KernelSU и APatch — ядерный root без модификации системного раздела. Классические чеки на su их не видят, поэтому проверяем их рабочие каталоги отдельно.",
            method = "java.io.File + faccessat(JNI)",
            evidence = ksu.map { ev(it.path, it.describe()) },
        )

        val modules = Sys.dirEntries("/data/adb/modules")
        out += signal(
            id = "modules_installed",
            title = "Установленные root-модули",
            triggered = modules.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "Список модулей читается напрямую — это сразу показывает, что именно подмешано в систему (включая скрывалки).",
            method = "readdir /data/adb/modules",
            evidence = modules.take(20).map { ev("module", it) },
        )

        val magiskSockets = ctx.unixSockets.lineSequence()
            .filter { it.contains("magisk", true) || it.contains("ksu", true) }
            .take(10).toList()
        out += signal(
            id = "magisk_socket",
            title = "Живой сокет root-демона",
            triggered = magiskSockets.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Абстрактный unix-сокет демона виден в /proc/net/unix. Это признак НЕ просто установленного, а АКТИВНО РАБОТАЮЩЕГО root-демона.",
            method = "procfs: /proc/net/unix",
            evidence = magiskSockets.map { ev("socket", it.trim().takeLast(80)) },
        )

        val zygiskMaps = ctx.maps.filter { r ->
            val p = r.path.lowercase()
            p.contains("zygisk") || p.contains("magisk") || p.contains("lspd") || p.contains("riru")
        }
        out += signal(
            id = "zygisk_in_process",
            title = "Zygisk / Riru внутри нашего процесса",
            triggered = zygiskMaps.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 100,
            why = "В адресном пространстве приложения замаплены библиотеки root-фреймворка — то есть в нас уже влезли.",
            method = "procfs: /proc/self/maps",
            evidence = zygiskMaps.take(10).map { ev("region", it.path) },
        )

        val nativeMaps = dev.vroot.checker.core.util.NativeBridge
            .mapsScan(listOf("magisk", "zygisk", "lspd", "riru", "ksu"))
        out += signal(
            id = "zygisk_native_view",
            title = "Нативный скан maps видит роот-артефакты",
            triggered = nativeMaps.isNotEmpty() && zygiskMaps.isEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Нативное чтение maps нашло то, чего не видит Java. Значит, чтение /proc/self/maps из Java подменено.",
            method = "jni: raw openat(/proc/self/maps)",
            evidence = nativeMaps.take(8).map { ev("line", it.takeLast(90)) },
        )

        return out
    }
}
