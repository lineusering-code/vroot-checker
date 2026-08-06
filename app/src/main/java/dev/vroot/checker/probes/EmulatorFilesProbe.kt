package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** Файловые артефакты QEMU / goldfish / VirtualBox / коммерческих эмуляторов. */
class EmulatorFilesProbe : BaseProbe() {
    override val id = "virt.emulator"
    override val displayName = "Файловые маркеры эмулятора"
    override val category = Category.EMULATOR

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val found = Sys.probeAll(Signatures.EMULATOR_FILES).filter { it.exists }
        out += signal(
            id = "emulator_files",
            title = "Файлы эмулятора на диске",
            triggered = found.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 92,
            why = "qemu_pipe, goldfish/ranchu init-скрипты, vbox-устройства и фирменные бинарники эмуляторов на реальном телефоне не существуют.",
            method = "java.io.File + faccessat(JNI)",
            evidence = found.map { ev(it.path, it.describe()) },
        )

        val goldfishTty = ctx.ttyDrivers.contains("goldfish", true)
        out += signal(
            id = "goldfish_tty",
            title = "Драйвер goldfish в /proc/tty/drivers",
            triggered = goldfishTty,
            severity = Severity.HIGH,
            confidence = 95,
            why = "goldfish — это виртуальная платформа Android Emulator. Её tty-драйвер не встречается на физическом железе.",
            method = "procfs: /proc/tty/drivers",
            evidence = listOf(ev("drivers", ctx.ttyDrivers.lineSequence().firstOrNull { it.contains("goldfish", true) } ?: "")),
        )

        val qemuProps = listOf("ro.kernel.qemu", "ro.kernel.android.qemud", "ro.boot.qemu", "qemu.hw.mainkeys", "qemu.sf.fake_camera")
            .map { it to ctx.prop(it) }.filter { it.second.isNotEmpty() }
        out += signal(
            id = "qemu_props",
            title = "QEMU-свойства системы",
            triggered = qemuProps.any { it.first.startsWith("ro.") && it.second == "1" } || qemuProps.size >= 2,
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Свойства ro.kernel.qemu и qemu.* выставляет сам эмулятор при загрузке системы.",
            method = "SystemProperties",
            evidence = qemuProps.map { ev(it.first, it.second) },
        )

        val kernel = Sys.readText("/proc/version")
        val kernelHit = listOf("goldfish", "ranchu", "microsoft", "virtualbox", "qemu").filter { kernel.contains(it, true) }
        out += signal(
            id = "kernel_banner",
            title = "Виртуальная платформа в баннере ядра",
            triggered = kernelHit.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "Строка версии ядра содержит имя виртуальной платформы, а не вендора SoC.",
            method = "procfs: /proc/version",
            evidence = listOf(ev("version", kernel.trim().take(160))) + kernelHit.map { ev("token", it) },
        )

        return out
    }
}
