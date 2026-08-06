package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/**
 * SELinux state. Read straight from sysfs and procfs rather than through
 * android.os.SELinux, whose reflection surface is trivial to stub out.
 */
class SelinuxProbe : BaseProbe() {
    override val id = "root.selinux"
    override val displayName = "SELinux state"
    override val category = Category.SELINUX

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val enforce = Sys.readText("/sys/fs/selinux/enforce").trim()
        out += signal(
            id = "permissive",
            title = "SELinux is permissive",
            triggered = enforce == "0",
            severity = Severity.HIGH,
            confidence = 95,
            why = "SELinux is always enforcing on a retail device. Permissive removes practically every boundary between processes.",
            method = "sysfs: /sys/fs/selinux/enforce",
            evidence = listOf(ev("enforce", enforce.ifEmpty { "<unavailable>" })),
        )

        val context = Sys.readText("/proc/self/attr/current").trim().trimEnd('\u0000')
        val badContext = listOf("magisk", "su", "init", "kernel").any {
            context.contains(":r:" + it + ":", ignoreCase = true)
        }
        out += signal(
            id = "bad_context",
            title = "Unexpected SELinux context for this process",
            triggered = badContext,
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "An ordinary app always runs in the untrusted_app domain. A magisk/su/init context means we were not started by the normal zygote.",
            method = "procfs: /proc/self/attr/current",
            evidence = listOf(ev("context", context.ifEmpty { "<empty>" })),
        )

        out += signal(
            id = "enforce_writable",
            title = "The enforce file is writable",
            triggered = Sys.canWrite("/sys/fs/selinux/enforce"),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Being able to write to enforce means the SELinux mode can be flipped at runtime.",
            method = "java.io.File.canWrite",
            evidence = listOf(ev("path", "/sys/fs/selinux/enforce")),
        )

        return out
    }
}
