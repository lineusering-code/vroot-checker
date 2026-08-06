package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/** Аномалии монтирования: overlay/tmpfs поверх системы и подмена mount namespace. */
class MountProbe : BaseProbe() {
    override val id = "root.mounts"
    override val displayName = "Точки монтирования"
    override val category = Category.MOUNTS

    private val systemMountPoints = listOf("/system", "/vendor", "/product", "/system_ext", "/apex")

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val mounts = ctx.mounts

        val overlays = mounts.filter { line ->
            val fs = line.split(" ").getOrNull(2).orEmpty()
            val point = line.split(" ").getOrNull(1).orEmpty()
            (fs == "overlay" || fs == "overlayfs") && systemMountPoints.any { point.startsWith(it) }
        }
        out += signal(
            id = "overlay_on_system",
            title = "overlayfs поверх системных разделов",
            triggered = overlays.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 80,
            why = "overlay на /system или /vendor — стандартный способ Magisk и KernelSU подменять системные файлы без записи в раздел (systemless).",
            method = "procfs: /proc/mounts",
            evidence = overlays.take(8).map { ev("mount", it.take(120)) },
        )

        val tmpfsHits = mounts.filter { line ->
            val parts = line.split(" ")
            val point = parts.getOrNull(1).orEmpty()
            val fs = parts.getOrNull(2).orEmpty()
            fs == "tmpfs" && (point == "/sbin" || point.startsWith("/system") || point == "/debug_ramdisk")
        }
        out += signal(
            id = "tmpfs_on_system",
            title = "tmpfs на /sbin или внутри /system",
            triggered = tmpfsHits.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Magisk подкладывает своё окружение в tmpfs, смонтированный на /sbin или /debug_ramdisk. На стоке там tmpfs не бывает.",
            method = "procfs: /proc/mounts",
            evidence = tmpfsHits.take(8).map { ev("mount", it.take(120)) },
        )

        val rwSystem = mounts.filter { line ->
            val parts = line.split(" ")
            val point = parts.getOrNull(1).orEmpty()
            val opts = parts.getOrNull(3).orEmpty()
            systemMountPoints.any { point == it } && opts.split(",").contains("rw")
        }
        out += signal(
            id = "system_rw",
            title = "Системный раздел смонтирован на запись",
            triggered = rwSystem.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "На нормальном устройстве /system всегда ro. rw означает выполненный remount с правами root.",
            method = "procfs: /proc/mounts",
            evidence = rwSystem.take(5).map { ev("mount", it.take(120)) },
        )

        // Классика: Magisk прячет свои монтирования в отдельном namespace,
        // и два источника начинают противоречить друг другу.
        val fromMounts = mounts.mapNotNull { it.split(" ").getOrNull(1) }.toSet()
        val fromMountInfo = ctx.mountInfo.mapNotNull { it.split(" ").getOrNull(4) }.toSet()
        val onlyInInfo = (fromMountInfo - fromMounts).filter { it.startsWith("/") }
        val onlyInMounts = (fromMounts - fromMountInfo).filter { it.startsWith("/") }
        val delta = onlyInInfo.size + onlyInMounts.size
        out += signal(
            id = "mount_namespace_mismatch",
            title = "/proc/mounts и /proc/self/mountinfo расходятся",
            triggered = delta > 3,
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Два описания одного и того же namespace должны совпадать. Сильное расхождение — след манипуляций с mount namespace (MagiskHide / DenyList).",
            method = "procfs cross-check",
            evidence = listOf(
                ev("only_in_mountinfo", onlyInInfo.take(5).joinToString()),
                ev("only_in_mounts", onlyInMounts.take(5).joinToString()),
                ev("delta", delta),
            ),
        )

        val magiskInMountInfo = ctx.mountInfo.filter { it.contains("magisk", true) || it.contains("worker", true) }
        out += signal(
            id = "magisk_mount_source",
            title = "Magisk-источники в mountinfo",
            triggered = magiskInMountInfo.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Имена источников вида magisk/worker остаются в mountinfo даже тогда, когда файлы уже скрыты.",
            method = "procfs: /proc/self/mountinfo",
            evidence = magiskInMountInfo.take(6).map { ev("line", it.take(120)) },
        )

        return out
    }
}
