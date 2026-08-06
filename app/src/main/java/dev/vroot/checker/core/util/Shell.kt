package dev.vroot.checker.core.util

import java.io.BufferedReader
import java.util.concurrent.TimeUnit

data class ShellResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean,
    val spawnFailed: Boolean = false,
) {
    val ok: Boolean get() = !spawnFailed && !timedOut && exitCode == 0
    val combined: String get() = (stdout + "\n" + stderr).trim()
}

object Shell {

    fun exec(cmd: Array<String>, timeoutMs: Long = 1000): ShellResult {
        var process: Process? = null
        return try {
            process = ProcessBuilder(*cmd).redirectErrorStream(false).start()
            val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            val out = process.inputStream.bufferedReader().use(BufferedReader::readText)
            val err = process.errorStream.bufferedReader().use(BufferedReader::readText)
            if (!finished) {
                process.destroyForcibly()
                ShellResult(-1, out, err, timedOut = true)
            } else {
                ShellResult(process.exitValue(), out, err, timedOut = false)
            }
        } catch (t: Throwable) {
            ShellResult(-1, "", t.message ?: "", timedOut = false, spawnFailed = true)
        } finally {
            runCatching { process?.destroy() }
        }
    }

    /** `which <bin>` — ищет бинарь по PATH так, как это сделал бы сам рут-менеджер. */
    fun which(bin: String, timeoutMs: Long = 800): String? {
        val r = exec(arrayOf("which", bin), timeoutMs)
        val line = r.stdout.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }
        return line?.takeIf { it.startsWith("/") }
    }

    /** Пробует запустить `su -c id` и понять, дали ли нам uid=0. */
    fun trySuIdentity(timeoutMs: Long = 1200): ShellResult = exec(arrayOf("su", "-c", "id"), timeoutMs)
}
