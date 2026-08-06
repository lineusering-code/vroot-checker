package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge
import dev.vroot.checker.core.util.ProcMaps

/** Инлайн-хуки в libc и чужой исполняемый код в памяти. */
class NativeHookProbe : BaseProbe() {
    override val id = "hook.native"
    override val displayName = "Нативные хуки и инжект кода"
    override val category = Category.HOOK_FRAMEWORK

    private val watchedSymbols = listOf(
        "libc.so" to "open",
        "libc.so" to "openat",
        "libc.so" to "read",
        "libc.so" to "fopen",
        "libc.so" to "__system_property_get",
        "libdl.so" to "dlopen",
    )

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val patched = watchedSymbols.mapNotNull { (lib, sym) ->
            val verdict = NativeBridge.inlineHookCheck(lib, sym)
            if (verdict == 1) (lib + "!" + sym) else null
        }
        out += signal(
            id = "inline_hooks",
            title = "Прологи функций libc пропатчены",
            triggered = patched.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 85,
            why = "Первые инструкции функции заменены безусловным переходом — так выглядит трамплин, установленный Dobby / frida-gum / Substrate. Значит, файловым вызовам доверять нельзя.",
            method = "jni: анализ пролога через dlsym",
            evidence = patched.map { ev("symbol", it) },
        )

        val anonExec = ProcMaps.suspiciousAnonExec(ctx.maps)
        out += signal(
            id = "anon_exec",
            title = "Исполняемые анонимные регионы памяти",
            triggered = anonExec.size > 2,
            severity = Severity.MEDIUM,
            confidence = 60,
            why = "Крупные rx-регионы без файла-источника — типичный след инжектированного кода (хотя часть даёт штатный JIT в ART, поэтому вес умеренный).",
            method = "procfs: /proc/self/maps",
            evidence = anonExec.take(6).map {
                ev(java.lang.Long.toHexString(it.start), it.perms + " size=" + it.size)
            },
        )

        val deleted = ctx.maps.filter { it.path.contains("(deleted)") }
        out += signal(
            id = "deleted_mappings",
            title = "В памяти замаплены удалённые файлы",
            triggered = deleted.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 75,
            why = "Загрузить .so и тут же удалить файл — классический способ скрыть инжектированную библиотеку от проверок по пути.",
            method = "procfs: /proc/self/maps",
            evidence = deleted.take(6).map { ev("region", it.path) },
        )

        val nonAppLibs = ctx.maps.filter { r ->
            r.path.endsWith(".so") &&
                !r.path.startsWith("/system") && !r.path.startsWith("/apex") &&
                !r.path.startsWith("/vendor") && !r.path.startsWith("/product") &&
                !r.path.contains(ctx.selfPackage)
        }
        out += signal(
            id = "foreign_libs",
            title = "Загружены .so из нетипичных мест",
            triggered = nonAppLibs.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 70,
            why = "Нативные библиотеки должны приходить из системных разделов или из каталога самого приложения. Всё остальное кто-то подсунул.",
            method = "procfs: /proc/self/maps",
            evidence = nonAppLibs.take(8).map { ev("lib", it.path) },
        )

        return out
    }
}
