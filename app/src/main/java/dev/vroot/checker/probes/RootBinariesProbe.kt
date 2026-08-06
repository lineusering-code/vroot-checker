package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Shell
import dev.vroot.checker.core.util.Sys

/**
 * Looks for su/busybox/magisk binaries through three independent channels:
 * java.io.File, a raw JNI syscall and PATH resolution. Using more than one
 * channel is the point - a hider that patches one of them usually leaves the
 * others answering truthfully.
 */
class RootBinariesProbe : BaseProbe() {
    override val id = "root.binaries"
    override val displayName = "Root binaries and PATH"
    override val category = Category.ROOT_BINARIES
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val suProbes = Sys.probeAll(Signatures.SU_PATHS)
        val suFound = suProbes.filter { it.exists }
        out += signal(
            id = "su_binary",
            title = "su binary on disk",
            triggered = suFound.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = if (suFound.any { it.executable }) 100 else 90,
            why = "su is the entry point for privilege escalation. On a stock build it does not exist at any of the known paths.",
            method = "java.io.File + faccessat(JNI)",
            evidence = suFound.map { ev(it.path, it.describe()) },
        )

        val mismatched = suProbes.filter { it.mismatch }
        out += signal(
            id = "su_channel_mismatch",
            title = "su lookups disagree between channels",
            triggered = mismatched.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "java.io.File and a direct syscall return different answers for the same path. That is what a hider looks like: the Java layer is patched and libc is forgotten.",
            method = "cross-check java vs jni",
            evidence = mismatched.map { ev(it.path, it.describe()) },
        )

        val tools = Sys.probeAll(Signatures.ROOT_TOOL_PATHS).filter { it.exists }
        out += signal(
            id = "root_tooling",
            title = "Supporting root tooling",
            triggered = tools.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 80,
            why = "busybox, daemonsu, supolicy, resetprop and Superuser.apk ship alongside a root manager and are not present on a clean system.",
            method = "java.io.File + faccessat(JNI)",
            evidence = tools.map { ev(it.path, it.describe()) },
        )

        if (ctx.config.allowShell) {
            val which = listOf("su", "busybox", "magisk", "ksud").mapNotNull { bin ->
                Shell.which(bin)?.let { bin to it }
            }
            out += signal(
                id = "which_su",
                title = "Root binaries reachable through PATH",
                triggered = which.isNotEmpty(),
                severity = Severity.HIGH,
                confidence = 90,
                why = "If which resolves the binary it sits in this process's PATH, meaning nobody is even trying to hide it.",
                method = "exec: which",
                evidence = which.map { ev(it.first, it.second) },
            )

            val su = Shell.trySuIdentity()
            val gotRoot = su.combined.contains("uid=0")
            out += signal(
                id = "su_exec",
                title = "Invoking su returned uid=0",
                triggered = gotRoot,
                severity = Severity.CRITICAL,
                confidence = 100,
                why = "A root shell was actually obtained. This is not a hint, it is the fact itself.",
                method = "exec: su -c id",
                evidence = listOf(ev("output", su.combined.take(200)), ev("spawnFailed", su.spawnFailed)),
            )
        }

        return out
    }
}
