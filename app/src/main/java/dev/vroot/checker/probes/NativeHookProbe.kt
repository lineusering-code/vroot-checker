package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge
import dev.vroot.checker.core.util.ProcMaps

/** Inline hooks in libc and foreign executable code in our address space. */
class NativeHookProbe : BaseProbe() {
    override val id = "hook.native"
    override val displayName = "Native hooks and code injection"
    override val category = Category.HOOK_FRAMEWORK

    private val watchedSymbols = listOf(
        "libc.so" to "open",
        "libc.so" to "openat",
        "libc.so" to "read",
        "libc.so" to "fopen",
        "libc.so" to "__system_property_get",
        "libdl.so" to "dlopen",
    )

    /** Deleted mappings that every healthy ART process has. */
    private val benignDeleted = listOf(
        "/memfd:", "/dev/ashmem", "/dev/binderfs", "anon_", "dalvik-", "[anon:",
    )

    /** Only real code can carry an injected payload. */
    private val codeSuffixes = listOf(".so", ".apk", ".jar", ".dex", ".oat", ".odex", ".vdex")

    private val trustedLibRoots = listOf(
        "/system/", "/system_ext/", "/apex/", "/vendor/", "/product/", "/odm/",
    )

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val patched = watchedSymbols.mapNotNull { (lib, sym) ->
            val verdict = NativeBridge.inlineHookCheck(lib, sym)
            if (verdict == 1) (lib + "!" + sym) else null
        }
        out += signal(
            id = "inline_hooks",
            title = "libc function prologues are patched",
            triggered = patched.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 85,
            why = "The first instructions of the function were replaced with an unconditional branch — the shape of a trampoline planted by Dobby, frida-gum or Substrate. File-system calls can no longer be trusted.",
            method = "jni: prologue analysis via dlsym",
            evidence = patched.map { ev("symbol", it) },
        )

        val anonExec = ProcMaps.suspiciousAnonExec(ctx.maps)
        out += signal(
            id = "anon_exec",
            title = "Executable anonymous memory regions",
            triggered = anonExec.size > 2,
            severity = Severity.MEDIUM,
            confidence = 60,
            why = "Large rx regions with no backing file are a classic sign of injected code, although the ART JIT legitimately creates some, hence the moderate weight.",
            method = "procfs: /proc/self/maps",
            evidence = anonExec.take(6).map {
                ev(java.lang.Long.toHexString(it.start), it.perms + " size=" + it.size)
            },
        )

        val deleted = ctx.maps.filter { r ->
            val p = r.path
            p.contains("(deleted)") &&
                benignDeleted.none { p.startsWith(it) || p.contains(it) } &&
                codeSuffixes.any { p.contains(it) }
        }
        out += signal(
            id = "deleted_mappings",
            title = "Deleted code files are mapped into memory",
            triggered = deleted.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 75,
            why = "Loading a .so and immediately unlinking it is the classic way to hide an injected library from path-based checks. JIT caches and ashmem regions are excluded: every normal ART process shows those as deleted.",
            method = "procfs: /proc/self/maps",
            evidence = deleted.take(6).map { ev("region", it.path) },
        )

        val nonAppLibs = ctx.maps.filter { r ->
            r.path.endsWith(".so") &&
                trustedLibRoots.none { r.path.startsWith(it) } &&
                !r.path.contains(ctx.selfPackage)
        }
        out += signal(
            id = "foreign_libs",
            title = ".so files loaded from unusual locations",
            triggered = nonAppLibs.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 70,
            why = "Native libraries should come from a read-only system partition or from this app's own directory. Anything else was placed there by somebody.",
            method = "procfs: /proc/self/maps",
            evidence = nonAppLibs.take(8).map { ev("lib", it.path) },
        )

        return out
    }
}
