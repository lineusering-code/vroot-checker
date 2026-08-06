package dev.vroot.checker.core.model

import java.util.Collections

enum class LogLevel(val tag: String) {
    TRACE("TRC"),
    INFO("INF"),
    HIT("HIT"),
    CLEAN("OK "),
    WARN("WRN"),
    ERROR("ERR"),
}

/**
 * Одна строка живого лога сканирования.
 * [detail] — многострочное объяснение (что нашли и почему это важно),
 * рендерится в UI под свёрткой.
 */
data class LogLine(
    val at: Long,
    val sinceStartMs: Long,
    val level: LogLevel,
    val tag: String,
    val message: String,
    val detail: String? = null,
)

/** Потокобезопасный сборщик лога: пробы пишут в него параллельно. */
class ScanLog(private val startedAt: Long = System.currentTimeMillis()) {

    private val lines: MutableList<LogLine> = Collections.synchronizedList(ArrayList<LogLine>(512))

    fun add(level: LogLevel, tag: String, message: String, detail: String? = null) {
        val now = System.currentTimeMillis()
        lines.add(LogLine(now, now - startedAt, level, tag, message, detail))
    }

    fun trace(tag: String, message: String, detail: String? = null) = add(LogLevel.TRACE, tag, message, detail)
    fun info(tag: String, message: String, detail: String? = null) = add(LogLevel.INFO, tag, message, detail)
    fun warn(tag: String, message: String, detail: String? = null) = add(LogLevel.WARN, tag, message, detail)
    fun error(tag: String, message: String, detail: String? = null) = add(LogLevel.ERROR, tag, message, detail)

    /** Логирует сигнал вместе с объяснением и уликами. */
    fun signal(tag: String, s: Signal) {
        val evidence = s.evidence.joinToString("\n") { "  • " + it.key + " = " + it.value }
        val detail = buildString {
            append("Почему: ").append(s.why)
            append("\nМетод: ").append(s.method)
            append("\nВес: ").append(s.severity.label)
                .append(" · уверенность ").append(s.confidence).append("%")
                .append(" · вклад ").append(s.score)
            if (evidence.isNotEmpty()) append("\nУлики:\n").append(evidence)
        }
        add(
            level = if (s.triggered) LogLevel.HIT else LogLevel.CLEAN,
            tag = tag,
            message = (if (s.triggered) "[+] " else "[-] ") + s.id + " — " + s.title,
            detail = detail,
        )
    }

    fun snapshot(): List<LogLine> = synchronized(lines) { lines.sortedBy { it.at }.toList() }
}
