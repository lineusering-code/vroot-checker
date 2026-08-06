package dev.vroot.checker.probes

import android.os.Debug
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge

/** Отладчик, ptrace-трейсер и seccomp. */
class DebuggerProbe : BaseProbe() {
    override val id = "debug.tracer"
    override val displayName = "Отладка и трассировка"
    override val category = Category.DEBUGGER

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val tracerPid = NativeBridge.tracerPid()
        out += signal(
            id = "tracer_pid",
            title = "К процессу прицеплён трассировщик",
            triggered = tracerPid > 0,
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Поле TracerPid в /proc/self/status отлично от нуля: кто-то выполнил PTRACE_ATTACH и читает/меняет нашу память. Именно так работают frida-server и gdb.",
            method = "procfs: /proc/self/status",
            evidence = listOf(ev("TracerPid", tracerPid)),
        )

        val jdwp = runCatching { Debug.isDebuggerConnected() }.getOrDefault(false)
        val waiting = runCatching { Debug.waitingForDebugger() }.getOrDefault(false)
        out += signal(
            id = "jdwp",
            title = "Подключён Java-отладчик",
            triggered = jdwp || waiting,
            severity = Severity.HIGH,
            confidence = 95,
            why = "JDWP-сессия позволяет ставить точки останова и подменять значения переменных на лету.",
            method = "android.os.Debug",
            evidence = listOf(ev("isDebuggerConnected", jdwp), ev("waitingForDebugger", waiting)),
        )

        val ptraceSelf = NativeBridge.ptraceSelfTest()
        out += signal(
            id = "ptrace_self",
            title = "Слот ptrace уже занят",
            triggered = ptraceSelf == 0,
            severity = Severity.HIGH,
            confidence = 80,
            why = "Процесс может трассироваться только одним трейсером. Если наш контрольный ptrace не прошёл — слот занял кто-то другой.",
            method = "jni: ptrace(PTRACE_TRACEME) в fork-дочернем процессе",
            evidence = listOf(ev("result", ptraceSelf)),
        )

        val seccomp = NativeBridge.seccompMode()
        out += signal(
            id = "seccomp_off",
            title = "seccomp-фильтр отключён",
            triggered = seccomp == 0,
            severity = Severity.LOW,
            confidence = 55,
            why = "Штатный zygote вешает на приложения seccomp-фильтр (режим 2). Нулевой режим встречается на модифицированных сборках и в контейнерах.",
            method = "procfs: Seccomp в /proc/self/status",
            evidence = listOf(ev("seccomp_mode", seccomp)),
        )

        return out
    }
}
