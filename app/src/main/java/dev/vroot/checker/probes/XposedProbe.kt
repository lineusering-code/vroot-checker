package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** Xposed / LSPosed / Riru / Substrate: classes, files and call-stack traces. */
class XposedProbe : BaseProbe() {
    override val id = "hook.xposed"
    override val displayName = "Xposed / LSPosed / Substrate"
    override val category = Category.HOOK_FRAMEWORK

    private val stackTokens = listOf(
        "xposed", "lspd", "lsplant", "substrate", "sandhook", "whale", "pine",
    )

    /** Our own package obviously mentions these words. Never count it. */
    private val selfPrefix = "dev.vroot.checker"

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val classes = Signatures.XPOSED_CLASSES.filter { name ->
            runCatching { Class.forName(name, false, javaClass.classLoader); true }.getOrDefault(false)
        }
        out += signal(
            id = "classes_loadable",
            title = "Hook framework classes resolve in our classloader",
            triggered = classes.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "XposedBridge and its forks are injected into every process they instrument. If the class resolves, the framework is active right here.",
            method = "Class.forName",
            evidence = classes.map { ev("class", it) },
        )

        val files = Sys.probeAll(Signatures.XPOSED_PATHS).filter { it.exists }
        out += signal(
            id = "framework_files",
            title = "Xposed / LSPosed / Riru files on disk",
            triggered = files.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 88,
            why = "XposedBridge.jar, /data/adb/lspd and the riru directories ship only with an interception framework.",
            method = "java.io.File + faccessat(JNI)",
            evidence = files.map { ev(it.path, it.describe()) },
        )

        val stack = runCatching { throw Exception("vroot-stack-probe") }
            .exceptionOrNull()?.stackTrace.orEmpty()
        val stackHits = stack.filter { el ->
            val cn = el.className
            !cn.startsWith(selfPrefix) && stackTokens.any { PathTokens.containsToken(cn, it) }
        }
        out += signal(
            id = "stack_injection",
            title = "Hook framework frames in our call stack",
            triggered = stackHits.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "When a method is actively hooked, the framework's own frames appear between our calls. Frames from this app are excluded, otherwise the probe reports itself.",
            method = "stack trace inspection",
            evidence = stackHits.take(6).map { ev(it.className, it.methodName) },
        )

        val libHits = ctx.maps.filter { r ->
            PathTokens.suspiciousPath(r.path, Signatures.HOOK_LIB_TOKENS)
        }
        out += signal(
            id = "hook_libs_mapped",
            title = "Interception libraries mapped into the process",
            triggered = libHits.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "libsubstrate, libdobby, lsplant, sandhook and friends exist for one purpose: rewriting somebody else's code at runtime.",
            method = "procfs: /proc/self/maps",
            evidence = libHits.take(10).map { ev("region", it.path) },
        )

        val xposedProp = ctx.prop("ro.xposed.version")
        out += signal(
            id = "xposed_prop",
            title = "ro.xposed.version is set",
            triggered = xposedProp.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 95,
            why = "The Xposed installer sets this property itself.",
            method = "SystemProperties",
            evidence = listOf(ev("ro.xposed.version", xposedProp)),
        )

        return out
    }
}
