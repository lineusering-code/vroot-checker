package dev.vroot.checker.core.util

import android.util.Log

/**
 * Тонкая обёртка над libvroot.so.
 *
 * Смысл нативного слоя: обойти Java-хуки. Проверки идут прямыми syscall'ами
 * (faccessat / openat / readlinkat), а не через java.io.File, который
 * элементарно перехватывается Xposed/LSPosed.
 *
 * Все вызовы обёрнуты: если библиотека не загрузилась (например, ABI не тот),
 * движок просто теряет часть чеков, а не падает.
 */
object NativeBridge {

    val available: Boolean = try {
        System.loadLibrary("vroot")
        true
    } catch (t: Throwable) {
        Log.w("vroot", "native layer unavailable: " + t.message)
        false
    }

    // --- raw JNI ---
    private external fun nativeAccess(path: String): Boolean
    private external fun nativeReadFile(path: String, maxBytes: Int): String?
    private external fun nativeGetProp(key: String): String
    private external fun nativeTracerPid(): Int
    private external fun nativePtraceSelfTest(): Int
    private external fun nativeSeccompMode(): Int
    private external fun nativeMapsScan(needles: Array<String>): Array<String>
    private external fun nativeInlineHookCheck(lib: String, symbol: String): Int
    private external fun nativeOpenDirCount(path: String): Int
    private external fun nativeReadlink(path: String): String?
    private external fun nativeUid(): Int

    // --- safe wrappers ---
    fun access(path: String): Boolean = safe(false) { nativeAccess(path) }

    fun readFile(path: String, maxBytes: Int = 512 * 1024): String? = safe(null) { nativeReadFile(path, maxBytes) }

    fun getProp(key: String): String = safe("") { nativeGetProp(key) }

    /** PID трассировщика из /proc/self/status; 0 — никто не привязан. */
    fun tracerPid(): Int = safe(-1) { nativeTracerPid() }

    /** 0 — self-attach удался (чисто), 1 — уже кто-то трассирует, -1 — неизвестно. */
    fun ptraceSelfTest(): Int = safe(-1) { nativePtraceSelfTest() }

    /** 0 disabled, 1 strict, 2 filter, -1 unknown. */
    fun seccompMode(): Int = safe(-1) { nativeSeccompMode() }

    /** Скан /proc/self/maps нативно (Java-хуки не видят этот путь). */
    fun mapsScan(needles: List<String>): List<String> =
        safe(emptyList()) { nativeMapsScan(needles.toTypedArray()).toList() }

    /** 1 — пролог функции пропатчен (inline hook), 0 — чисто, -1 — не проверить. */
    fun inlineHookCheck(lib: String, symbol: String): Int = safe(-1) { nativeInlineHookCheck(lib, symbol) }

    fun openDirCount(path: String): Int = safe(-1) { nativeOpenDirCount(path) }

    fun readlink(path: String): String? = safe(null) { nativeReadlink(path) }

    fun uid(): Int = safe(-1) { nativeUid() }

    private inline fun <T> safe(fallback: T, block: () -> T): T =
        if (!available) fallback else try {
            block()
        } catch (t: Throwable) {
            fallback
        }
}
