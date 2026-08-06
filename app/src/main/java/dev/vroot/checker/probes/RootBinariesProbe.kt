package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Shell
import dev.vroot.checker.core.util.Sys

/** Поиск su/busybox/magisk-бинарников тремя каналами: File, JNI-syscall и PATH. */
class RootBinariesProbe : BaseProbe() {
    override val id = "root.binaries"
    override val displayName = "Root-бинарники и PATH"
    override val category = Category.ROOT_BINARIES
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val suProbes = Sys.probeAll(Signatures.SU_PATHS)
        val suFound = suProbes.filter { it.exists }
        out += signal(
            id = "su_binary",
            title = "Бинарник su на диске",
            triggered = suFound.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = if (suFound.any { it.executable }) 100 else 90,
            why = "Файл su — это точка входа для повышения привилегий. На стоковой прошивке его не существует ни по одному из известных путей.",
            method = "java.io.File + faccessat(JNI)",
            evidence = suFound.map { ev(it.path, it.describe()) },
        )

        val mismatched = suProbes.filter { it.mismatch }
        out += signal(
            id = "su_channel_mismatch",
            title = "Каналы проверки su расходятся",
            triggered = mismatched.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "java.io.File и прямой syscall дают разный ответ по одному и тому же пути. Так выглядит работа скрывалки: патчат Java-уровень и забывают про libc.",
            method = "cross-check java vs jni",
            evidence = mismatched.map { ev(it.path, it.describe()) },
        )

        val tools = Sys.probeAll(Signatures.ROOT_TOOL_PATHS).filter { it.exists }
        out += signal(
            id = "root_tooling",
            title = "Сопутствующий root-тулинг",
            triggered = tools.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 80,
            why = "busybox, daemonsu, supolicy, resetprop и Superuser.apk ставятся вместе с root-менеджером и не встречаются на чистой системе.",
            method = "java.io.File + faccessat(JNI)",
            evidence = tools.map { ev(it.path, it.describe()) },
        )

        if (ctx.config.allowShell) {
            val which = listOf("su", "busybox", "magisk", "ksud").mapNotNull { bin ->
                Shell.which(bin)?.let { bin to it }
            }
            out += signal(
                id = "which_su",
                title = "Root-бинарники доступны через PATH",
                triggered = which.isNotEmpty(),
                severity = Severity.HIGH,
                confidence = 90,
                why = "Если which находит бинарник, он лежит в PATH процесса — значит его даже не пытаются прятать.",
                method = "exec: which",
                evidence = which.map { ev(it.first, it.second) },
            )

            val su = Shell.trySuIdentity()
            val gotRoot = su.combined.contains("uid=0")
            out += signal(
                id = "su_exec",
                title = "Вызов su выдал uid=0",
                triggered = gotRoot,
                severity = Severity.CRITICAL,
                confidence = 100,
                why = "Мы реально получили root-оболочку. Это не косвенный признак, а факт.",
                method = "exec: su -c id",
                evidence = listOf(ev("output", su.combined.take(200)), ev("spawnFailed", su.spawnFailed)),
            )
        }

        return out
    }
}
