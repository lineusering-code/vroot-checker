package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge
import dev.vroot.checker.core.util.Sys

/** Magisk / Zygisk / KernelSU / APatch traces in the filesystem, sockets and memory. */
class RootManagerProbe : BaseProbe() {
    override val id = "root.manager"
    override val displayName = "Root managers (Magisk / KernelSU / APatch)"
    override val category = Category.ROOT_MANAGER
    override val timeoutMs = 2000L

    private val rootTokens = listOf("magisk", "zygisk", "lspd", "riru", "ksu", "apatch")

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val magisk = Sys.probeAll(Signatures.MAGISK_PATHS).filter { it.exists }
        out += signal(
            id = "magisk_files",
            title = "Magisk artifacts in the filesystem",
            triggered = magisk.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Only Magisk creates /data/adb/magisk, /data/adb/modules and /sbin/.magisk. DenyList hides mounts but usually leaves the directories themselves readable.",
            method = "java.io.File + faccessat(JNI)",
            evidence = magisk.map { ev(it.path, it.describe()) },
        )

        val ksu = Sys.probeAll(Signatures.KERNELSU_PATHS).filter { it.exists }
        out += signal(
            id = "kernelsu_apatch",
            title = "KernelSU / APatch traces",
            triggered = ksu.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 92,
            why = "KernelSU and APatch are kernel-level root that never touches the system partition, so classic su checks miss them. Their working directories are checked separately.",
            method = "java.io.File + faccessat(JNI)",
            evidence = ksu.map { ev(it.path, it.describe()) },
        )

        val modules = Sys.dirEntries("/data/adb/modules")
        out += signal(
            id = "modules_installed",
            title = "Installed root modules",
            triggered = modules.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "Reading the module list directly shows exactly what has been grafted onto the system, hiding modules included.",
            method = "readdir /data/adb/modules",
            evidence = modules.take(20).map { ev("module", it) },
        )

        val magiskSockets = ctx.unixSockets.lineSequence()
            .filter { line -> PathTokens.anyToken(line, listOf("magisk", "ksu", "apatch")) }
            .take(10).toList()
        out += signal(
            id = "magisk_socket",
            title = "Live root daemon socket",
            triggered = magiskSockets.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "The daemon's abstract unix socket is visible in /proc/net/unix. That means root is not merely installed, it is running right now.",
            method = "procfs: /proc/net/unix",
            evidence = magiskSockets.map { ev("socket", it.trim().takeLast(80)) },
        )

        val zygiskMaps = ctx.maps.filter { r -> PathTokens.suspiciousPath(r.path, rootTokens) }
        out += signal(
            id = "zygisk_in_process",
            title = "Zygisk / Riru inside our own process",
            triggered = zygiskMaps.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 100,
            why = "Root framework libraries are mapped into this app's address space, meaning something has already climbed inside.",
            method = "procfs: /proc/self/maps",
            evidence = zygiskMaps.take(10).map { ev("region", it.path) },
        )

        // The native scan uses plain substring matching, so its output is
        // filtered with the same boundary rules before it counts as evidence.
        val nativeMaps = NativeBridge.mapsScan(rootTokens)
            .filter { line -> PathTokens.suspiciousPath(pathOf(line), rootTokens) }
        out += signal(
            id = "zygisk_native_view",
            title = "Native maps scan sees root artifacts that Java does not",
            triggered = nativeMaps.isNotEmpty() && zygiskMaps.isEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Reading /proc/self/maps through a raw syscall found entries missing from the Java view, which means the Java file API is being filtered.",
            method = "jni: raw openat(/proc/self/maps)",
            evidence = nativeMaps.take(8).map { ev("line", it.takeLast(90)) },
        )

        return out
    }

    /** A maps line is "addr perms offset dev inode   path". We only judge the path. */
    private fun pathOf(line: String): String {
        val idx = line.indexOf('/')
        return if (idx >= 0) line.substring(idx).trim() else ""
    }
}
