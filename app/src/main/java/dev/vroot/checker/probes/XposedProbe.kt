package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/** Xposed / LSPosed / Riru / Substrate: классы, файлы и следы в стеке вызовов. */
class XposedProbe : BaseProbe() {
    override val id = "hook.xposed"
    override val displayName = "Xposed / LSPosed / Substrate"
    override val category = Category.HOOK_FRAMEWORK

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val classes = Signatures.XPOSED_CLASSES.filter { name ->
            runCatching { Class.forName(name, false, javaClass.classLoader); true }.getOrDefault(false)
        }
        out += signal(
            id = "classes_loadable",
            title = "Классы хук-фреймворка доступны из нашего classloader",
            triggered = classes.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "XposedBridge и аналоги загружаются в каждый процесс, который они обрабатывают. Если класс резолвится — фреймворк активен именно здесь.",
            method = "Class.forName",
            evidence = classes.map { ev("class", it) },
        )

        val files = Sys.probeAll(Signatures.XPOSED_PATHS).filter { it.exists }
        out += signal(
            id = "framework_files",
            title = "Файлы Xposed / LSPosed / Riru",
            triggered = files.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 88,
            why = "XposedBridge.jar, /data/adb/lspd и каталоги riru ставятся только вместе с фреймворком перехвата.",
            method = "java.io.File + faccessat(JNI)",
            evidence = files.map { ev(it.path, it.describe()) },
        )

        val stack = runCatching { throw Exception("vroot-stack-probe") }
            .exceptionOrNull()?.stackTrace.orEmpty()
        val stackHits = stack.filter { el ->
            val cn = el.className.lowercase()
            cn.contains("xposed") || cn.contains("lspd") || cn.contains("lsplant") ||
                cn.contains("substrate") || cn.contains("sandhook") || cn.contains("epic")
        }
        out += signal(
            id = "stack_injection",
            title = "Следы хук-фреймворка в стеке вызовов",
            triggered = stackHits.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "При активном перехвате в стеке появляются кадры самого фреймворка между нашими вызовами.",
            method = "stack trace inspection",
            evidence = stackHits.take(6).map { ev(it.className, it.methodName) },
        )

        val libHits = ctx.maps.filter { r ->
            Signatures.HOOK_LIB_TOKENS.any { r.path.contains(it, ignoreCase = true) }
        }
        out += signal(
            id = "hook_libs_mapped",
            title = "Загружены библиотеки перехвата",
            triggered = libHits.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "libsubstrate, libdobby, lsplant, sandhook и подобные библиотеки нужны только для модификации чужого кода в рантайме.",
            method = "procfs: /proc/self/maps",
            evidence = libHits.take(10).map { ev("region", it.path) },
        )

        val xposedProp = ctx.prop("ro.xposed.version")
        out += signal(
            id = "xposed_prop",
            title = "Свойство ro.xposed.version выставлено",
            triggered = xposedProp.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 95,
            why = "Это свойство выставляет сам фреймворк Xposed при установке.",
            method = "SystemProperties",
            evidence = listOf(ev("ro.xposed.version", xposedProp)),
        )

        return out
    }
}
