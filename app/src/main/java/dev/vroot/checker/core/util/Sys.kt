package dev.vroot.checker.core.util

import java.io.File

/** Результат мультиканальной проверки существования пути. */
data class PathProbe(
    val path: String,
    val java: Boolean,
    val native: Boolean,
    val readable: Boolean,
    val executable: Boolean,
    val size: Long,
) {
    val exists: Boolean get() = java || native

    /**
     * Java говорит «нет», а нативный faccessat говорит «да» (или наоборот) —
     * значит кто-то перехватывает файловые вызовы на уровне JVM/libc.
     */
    val mismatch: Boolean get() = java != native

    fun describe(): String =
        "java=" + java + " jni=" + native + " r=" + readable + " x=" + executable + " size=" + size
}

object Sys {

    fun readText(path: String): String = try {
        val f = File(path)
        if (f.canRead()) f.readText() else NativeBridge.readFile(path) ?: ""
    } catch (t: Throwable) {
        NativeBridge.readFile(path) ?: ""
    }

    fun readLines(path: String): List<String> =
        readText(path).lineSequence().filter { it.isNotBlank() }.toList()

    fun exists(path: String): Boolean = try {
        File(path).exists()
    } catch (t: Throwable) {
        false
    }

    /** Проверка пути сразу несколькими каналами. */
    fun probe(path: String): PathProbe {
        val f = runCatching { File(path) }.getOrNull()
        val java = runCatching { f?.exists() == true }.getOrDefault(false)
        val native = NativeBridge.access(path)
        return PathProbe(
            path = path,
            java = java,
            native = native,
            readable = runCatching { f?.canRead() == true }.getOrDefault(false),
            executable = runCatching { f?.canExecute() == true }.getOrDefault(false),
            size = runCatching { f?.length() ?: 0L }.getOrDefault(0L),
        )
    }

    fun probeAll(paths: Collection<String>): List<PathProbe> = paths.map { probe(it) }

    fun dirEntries(path: String): List<String> = try {
        File(path).list()?.toList() ?: emptyList()
    } catch (t: Throwable) {
        emptyList()
    }

    fun canWrite(path: String): Boolean = try {
        val f = File(path)
        f.exists() && f.canWrite()
    } catch (t: Throwable) {
        false
    }

    /** Попытка реально создать файл — честнее, чем canWrite(). */
    fun canCreateFileIn(dir: String): Boolean = try {
        val probe = File(dir, ".vroot_" + System.nanoTime())
        val created = probe.createNewFile()
        if (created) probe.delete()
        created
    } catch (t: Throwable) {
        false
    }
}
