package dev.vroot.checker.probes

import android.os.Debug
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge

/** Debugger, ptrace tracer and seccomp state. */
class DebuggerProbe : BaseProbe() {
    override val id = "debug.tracer"
    override val displayName = "Debugging and tracing"
    override val category = Category.DEBUG

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val tracerPid = NativeBridge.tracerPid()
        out += signal(
            id = "tracer_pid",
            title = "A tracer is attached to this process",
            triggered = tracerPid > 0,
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "TracerPid in /proc/self/status is non-zero: somebody called PTRACE_ATTACH and is reading or rewriting our memory. That is exactly how frida-server and gdb operate.",
            method = "procfs: /proc/self/status",
            evidence = listOf(ev("TracerPid", tracerPid)),
        )

        val jdwp = runCatching { Debug.isDebuggerConnected() }.getOrDefault(false)
        val waiting = runCatching { Debug.waitingForDebugger() }.getOrDefault(false)
        out += signal(
            id = "jdwp",
            title = "A Java debugger is connected",
            triggered = jdwp || waiting,
            severity = Severity.HIGH,
            confidence = 95,
            why = "A JDWP session can set breakpoints and rewrite variables on the fly.",
            method = "android.os.Debug",
            evidence = listOf(ev("isDebuggerConnected", jdwp), ev("waitingForDebugger", waiting)),
        )

        // Contract of the native helper:
        //   0  -> the control attach succeeded, so nobody else is tracing us
        //   1  -> the attach was refused, somebody already holds the slot
        //  -1  -> could not determine
        val ptraceSelf = NativeBridge.ptraceSelfTest()
        out += signal(
            id = "ptrace_self",
            title = "The ptrace slot is already taken",
            triggered = ptraceSelf == 1,
            severity = Severity.HIGH,
            confidence = 80,
            why = "A process can only be traced by one tracer at a time. Our control attach was refused, so somebody else is holding the slot.",
            method = "jni: ptrace(PTRACE_ATTACH) from a forked child",
            evidence = listOf(ev("result", ptraceSelf), ev("meaning", if (ptraceSelf == 0) "attach succeeded, no tracer" else if (ptraceSelf == 1) "attach refused" else "undetermined")),
        )

        val seccomp = NativeBridge.seccompMode()
        out += signal(
            id = "seccomp_off",
            title = "seccomp filter is disabled",
            triggered = seccomp == 0,
            severity = Severity.LOW,
            confidence = 55,
            why = "The stock zygote installs a seccomp filter (mode 2) on every app. Mode 0 shows up on modified builds and in containers.",
            method = "procfs: Seccomp in /proc/self/status",
            evidence = listOf(ev("seccomp_mode", seccomp)),
        )

        return out
    }
}
