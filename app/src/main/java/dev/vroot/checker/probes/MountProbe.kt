package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/** Mount anomalies: overlay/tmpfs over the system tree and namespace tampering. */
class MountProbe : BaseProbe() {
    override val id = "root.mounts"
    override val displayName = "Mount points"
    override val category = Category.MOUNTS

    /** Where a systemless root would graft itself. /apex is deliberately absent. */
    private val systemMountPoints = listOf("/system", "/vendor", "/product", "/system_ext", "/apex")

    /**
     * Real, block-device backed system partitions. /apex is NOT one of them:
     * on every Android 10+ device it is a rw tmpfs holding the APEX mounts,
     * which used to make stock phones report a writable system partition.
     */
    private val realSystemPoints = listOf("/system", "/vendor", "/product", "/system_ext", "/odm")
    private val blockFilesystems = listOf("ext4", "erofs", "f2fs", "squashfs")

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
            title = "overlayfs on top of system partitions",
            triggered = overlays.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 80,
            why = "An overlay on /system or /vendor is how Magisk and KernelSU replace system files without writing to the partition (systemless mode).",
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
            title = "tmpfs on /sbin or inside /system",
            triggered = tmpfsHits.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Magisk stages its environment in a tmpfs mounted on /sbin or /debug_ramdisk. A stock device has no tmpfs there.",
            method = "procfs: /proc/mounts",
            evidence = tmpfsHits.take(8).map { ev("mount", it.take(120)) },
        )

        val rwSystem = mounts.filter { line ->
            val parts = line.split(" ")
            val point = parts.getOrNull(1).orEmpty()
            val fs = parts.getOrNull(2).orEmpty()
            val opts = parts.getOrNull(3).orEmpty()
            realSystemPoints.contains(point) &&
                blockFilesystems.contains(fs) &&
                opts.split(",").contains("rw")
        }
        out += signal(
            id = "system_rw",
            title = "System partition mounted read-write",
            triggered = rwSystem.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "A real system partition is always ro on a healthy device; rw means a root remount was performed. The /apex tmpfs is excluded because it is rw by design on every Android 10+ device.",
            method = "procfs: /proc/mounts",
            evidence = rwSystem.take(5).map { ev("mount", it.take(120)) },
        )

        // Classic tell: Magisk hides its mounts in a separate namespace and the
        // two procfs views start contradicting each other.
        val fromMounts = mounts.mapNotNull { it.split(" ").getOrNull(1) }.toSet()
        val fromMountInfo = ctx.mountInfo.mapNotNull { it.split(" ").getOrNull(4) }.toSet()
        val onlyInInfo = (fromMountInfo - fromMounts).filter { it.startsWith("/") }
        val onlyInMounts = (fromMounts - fromMountInfo).filter { it.startsWith("/") }
        val delta = onlyInInfo.size + onlyInMounts.size
        out += signal(
            id = "mount_namespace_mismatch",
            title = "/proc/mounts and /proc/self/mountinfo disagree",
            triggered = delta > 3,
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Two descriptions of the same namespace should match. A large delta is a trace of mount namespace manipulation (MagiskHide / DenyList).",
            method = "procfs cross-check",
            evidence = listOf(
                ev("only_in_mountinfo", onlyInInfo.take(5).joinToString()),
                ev("only_in_mounts", onlyInMounts.take(5).joinToString()),
                ev("delta", delta),
            ),
        )

        val magiskInMountInfo = ctx.mountInfo.filter { line ->
            PathTokens.anyToken(line, listOf("magisk", "ksu", "apatch")) ||
                line.contains("worker", ignoreCase = true)
        }
        out += signal(
            id = "magisk_mount_source",
            title = "Magisk mount sources in mountinfo",
            triggered = magiskInMountInfo.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Source names like magisk/worker survive in mountinfo even after the files themselves have been hidden.",
            method = "procfs: /proc/self/mountinfo",
            evidence = magiskInMountInfo.take(6).map { ev("line", it.take(120)) },
        )

        return out
    }
}
