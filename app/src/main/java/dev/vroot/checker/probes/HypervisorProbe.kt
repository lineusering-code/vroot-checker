package dev.vroot.checker.probes

import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** Признаки гипервизора и архитектурные нестыковки. */
class HypervisorProbe : BaseProbe() {
    override val id = "virt.hypervisor"
    override val displayName = "Гипервизор и архитектура"
    override val category = Category.HYPERVISOR

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val cpuinfo = ctx.cpuinfo

        out += signal(
            id = "hypervisor_flag",
            title = "Флаг hypervisor в /proc/cpuinfo",
            triggered = cpuinfo.contains("hypervisor", true),
            severity = Severity.HIGH,
            confidence = 90,
            why = "CPU сам сообщает, что код исполняется под гипервизором — это виртуальная машина, а не телефон.",
            method = "procfs: /proc/cpuinfo",
            evidence = listOf(ev("flags", cpuinfo.lineSequence().firstOrNull { it.contains("flags", true) }?.take(160) ?: "")),
        )

        val abis = Build.SUPPORTED_ABIS?.toList().orEmpty()
        val x86Only = abis.isNotEmpty() && abis.none { it.startsWith("arm") }
        out += signal(
            id = "x86_device",
            title = "Устройство только с x86-ABI",
            triggered = x86Only,
            severity = Severity.MEDIUM,
            confidence = 75,
            why = "Подавляющее большинство реальных Android-устройств — ARM. Чистый x86/x86_64 почти всегда эмулятор или Android-x86/WSA.",
            method = "Build.SUPPORTED_ABIS",
            evidence = listOf(ev("abis", abis.joinToString())),
        )

        val hypervisorNodes = listOf("/sys/hypervisor", "/proc/xen", "/sys/bus/vmbus", "/dev/kvm", "/dev/hvc0")
            .let { Sys.probeAll(it) }.filter { it.exists }
        out += signal(
            id = "hypervisor_nodes",
            title = "Узлы гипервизора в sysfs/dev",
            triggered = hypervisorNodes.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Наличие /sys/hypervisor, vmbus или /dev/kvm в гостевой системе — прямой признак виртуализации.",
            method = "faccessat(JNI)",
            evidence = hypervisorNodes.map { ev(it.path, it.describe()) },
        )

        val cores = Runtime.getRuntime().availableProcessors()
        val cpuHasSerial = cpuinfo.contains("Serial", true) || cpuinfo.contains("Hardware", true)
        out += signal(
            id = "cpuinfo_shape",
            title = "Нетипичный вид /proc/cpuinfo",
            triggered = !cpuHasSerial && abis.any { it.startsWith("arm") },
            severity = Severity.LOW,
            confidence = 55,
            why = "У реальных ARM-устройств в cpuinfo обычно есть строки Hardware/Serial. Их отсутствие типично для виртуальных CPU.",
            method = "procfs: /proc/cpuinfo",
            evidence = listOf(ev("cores", cores), ev("has_hardware_line", cpuHasSerial)),
        )

        return out
    }
}
