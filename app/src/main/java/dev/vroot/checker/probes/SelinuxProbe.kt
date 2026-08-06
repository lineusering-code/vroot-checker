package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

class SelinuxProbe : BaseProbe() {
    override val id = "root.selinux"
    override val displayName = "Состояние SELinux"
    override val category = Category.SELINUX

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val enforce = Sys.readText("/sys/fs/selinux/enforce").trim()
        out += signal(
            id = "permissive",
            title = "SELinux в режиме permissive",
            triggered = enforce == "0",
            severity = Severity.HIGH,
            confidence = 95,
            why = "На любом розничном устройстве SELinux всегда enforcing. Permissive снимает практически все ограничения между процессами.",
            method = "sysfs: /sys/fs/selinux/enforce",
            evidence = listOf(ev("enforce", enforce.ifEmpty { "<недоступно>" })),
        )

        val context = Sys.readText("/proc/self/attr/current").trim().trimEnd('\u0000')
        val badContext = listOf("magisk", "su", "init", "kernel").any {
            context.contains(":r:" + it + ":", ignoreCase = true)
        }
        out += signal(
            id = "bad_context",
            title = "Нетипичный SELinux-контекст процесса",
            triggered = badContext,
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "Обычное приложение всегда работает в домене untrusted_app. Контекст magisk/su/init означает, что нас запустил не штатный zygote.",
            method = "procfs: /proc/self/attr/current",
            evidence = listOf(ev("context", context.ifEmpty { "<пусто>" })),
        )

        out += signal(
            id = "enforce_writable",
            title = "Файл enforce доступен на запись",
            triggered = Sys.canWrite("/sys/fs/selinux/enforce"),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Возможность писать в enforce означает, что режим SELinux можно переключить на лету.",
            method = "java.io.File.canWrite",
            evidence = listOf(ev("path", "/sys/fs/selinux/enforce")),
        )

        return out
    }
}
