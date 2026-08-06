package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** File artifacts left by QEMU / goldfish / VirtualBox / commercial emulators. */
class EmulatorFilesProbe : BaseProbe() {
    override val id = "virt.emulator"
    override val displayName = "Emulator file markers"
    override val category = Category.EMULATOR

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val found = Sys.probeAll(Signatures.EMULATOR_FILES).filter { it.exists }
        out += signal(
            id = "emulator_files",
            title = "Emulator files on disk",
            triggered = found.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 92,
            why = "qemu_pipe, goldfish/ranchu init scripts, vbox devices and vendor emulator binaries do not exist on a real phone.",
            method = "java.io.File + faccessat(JNI)",
            evidence = found.map { ev(it.path, it.describe()) },
        )

        val goldfishTty = ctx.ttyDrivers.contains("goldfish", true)
        out += signal(
            id = "goldfish_tty",
            title = "goldfish driver in /proc/tty/drivers",
            triggered = goldfishTty,
            severity = Severity.HIGH,
            confidence = 95,
            why = "goldfish is the Android Emulator's virtual platform. Its tty driver is never present on physical hardware.",
            method = "procfs: /proc/tty/drivers",
            evidence = listOf(ev("drivers", ctx.ttyDrivers.lineSequence().firstOrNull { it.contains("goldfish", true) } ?: "")),
        )

        val qemuProps = listOf("ro.kernel.qemu", "ro.kernel.android.qemud", "ro.boot.qemu", "qemu.hw.mainkeys", "qemu.sf.fake_camera")
            .map { it to ctx.prop(it) }.filter { it.second.isNotEmpty() }
        out += signal(
            id = "qemu_props",
            title = "QEMU system properties",
            triggered = qemuProps.any { it.first.startsWith("ro.") && it.second == "1" } || qemuProps.size >= 2,
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "ro.kernel.qemu and the qemu.* properties are set by the emulator itself while the system boots.",
            method = "SystemProperties",
            evidence = qemuProps.map { ev(it.first, it.second) },
        )

        val kernel = Sys.readText("/proc/version")
        val kernelHit = listOf("goldfish", "ranchu", "microsoft", "virtualbox", "qemu").filter { kernel.contains(it, true) }
        out += signal(
            id = "kernel_banner",
            title = "Virtual platform named in the kernel banner",
            triggered = kernelHit.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "The kernel version string names a virtual platform instead of the SoC vendor.",
            method = "procfs: /proc/version",
            evidence = listOf(ev("version", kernel.trim().take(160))) + kernelHit.map { ev("token", it) },
        )

        return out
    }
}
