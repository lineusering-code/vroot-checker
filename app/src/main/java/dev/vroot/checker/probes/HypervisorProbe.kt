package dev.vroot.checker.probes

import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** Hypervisor traces and architectural inconsistencies. */
class HypervisorProbe : BaseProbe() {
    override val id = "virt.hypervisor"
    override val displayName = "Hypervisor and architecture"
    override val category = Category.HYPERVISOR

    /** Nodes that only ever exist inside a guest. */
    private val guestOnlyNodes = listOf("/proc/xen", "/sys/bus/vmbus", "/dev/kvm", "/dev/hvc0")

    /**
     * /sys/hypervisor itself is compiled into plenty of stock ARM kernels and
     * shows up as an empty unreadable directory, so it only counts when it
     * actually describes a hypervisor.
     */
    private val hypervisorDetails = listOf("/sys/hypervisor/type", "/sys/hypervisor/uuid", "/sys/hypervisor/version")

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val cpuinfo = ctx.cpuinfo

        out += signal(
            id = "hypervisor_flag",
            title = "hypervisor flag in /proc/cpuinfo",
            triggered = cpuinfo.contains("hypervisor", true),
            severity = Severity.HIGH,
            confidence = 90,
            why = "The CPU itself reports that code is running under a hypervisor. That is a virtual machine, not a phone.",
            method = "procfs: /proc/cpuinfo",
            evidence = listOf(ev("flags", cpuinfo.lineSequence().firstOrNull { it.contains("flags", true) }?.take(160) ?: "")),
        )

        val abis = Build.SUPPORTED_ABIS?.toList().orEmpty()
        val x86Only = abis.isNotEmpty() && abis.none { it.startsWith("arm") }
        out += signal(
            id = "x86_device",
            title = "x86-only ABI set",
            triggered = x86Only,
            severity = Severity.MEDIUM,
            confidence = 75,
            why = "The overwhelming majority of real Android devices are ARM. Pure x86/x86_64 is almost always an emulator, Android-x86 or WSA.",
            method = "Build.SUPPORTED_ABIS",
            evidence = listOf(ev("abis", abis.joinToString())),
        )

        val guestNodes = Sys.probeAll(guestOnlyNodes).filter { it.exists }
        val hvDetails = Sys.probeAll(hypervisorDetails).filter { it.exists }
        out += signal(
            id = "hypervisor_nodes",
            title = "Hypervisor nodes in sysfs/dev",
            triggered = guestNodes.isNotEmpty() || hvDetails.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "/dev/kvm, vmbus or a populated /sys/hypervisor inside the guest means virtualization. The bare /sys/hypervisor directory is ignored: stock ARM kernels ship it empty and unreadable.",
            method = "faccessat(JNI)",
            evidence = (guestNodes + hvDetails).map { ev(it.path, it.describe()) },
        )

        val cores = Runtime.getRuntime().availableProcessors()
        val cpuHasSerial = cpuinfo.contains("Serial", true) || cpuinfo.contains("Hardware", true)
        out += signal(
            id = "cpuinfo_shape",
            title = "No Hardware/Serial line in /proc/cpuinfo",
            triggered = !cpuHasSerial && abis.any { it.startsWith("arm") },
            severity = Severity.INFO,
            confidence = 30,
            why = "Older ARM devices printed Hardware/Serial lines and emulators often did not. Modern kernels dropped those lines on real hardware too, so this is context for the log rather than evidence.",
            method = "procfs: /proc/cpuinfo",
            evidence = listOf(ev("cores", cores), ev("has_hardware_line", cpuHasSerial)),
        )

        return out
    }
}
