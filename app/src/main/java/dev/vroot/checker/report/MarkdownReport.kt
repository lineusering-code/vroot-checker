package dev.vroot.checker.report

import dev.vroot.checker.About
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.core.model.LogLevel
import dev.vroot.checker.core.model.ProbeReport
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.model.Verdict
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Человекочитаемый отчёт в Markdown — годится для issue, чата или файла .md. */
object MarkdownReport {

    private fun ts(at: Long): String =
        SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.US).format(Date(at))

    private fun secs(ms: Long): String = String.format(Locale.US, "%.2f с", ms / 1000.0)

    private fun cell(v: Any?): String = v.toString().replace("|", "\\|").replace("\n", " ")

    private fun bar(value: Int, width: Int = 10): String {
        val filled = (value.coerceIn(0, 100) * width + 50) / 100
        return "█".repeat(filled) + "░".repeat(width - filled)
    }

    private fun badge(v: Verdict): String = when (v) {
        Verdict.CLEAN -> "🟢"
        Verdict.SUSPICIOUS -> "🟡"
        Verdict.COMPROMISED -> "🟠"
        Verdict.HOSTILE -> "🔴"
    }

    private fun mark(s: Severity): String = when (s) {
        Severity.INFO -> "ℹ️"
        Severity.LOW -> "🟡"
        Severity.MEDIUM -> "🟠"
        Severity.HIGH -> "🔴"
        Severity.CRITICAL -> "☠️"
    }

    fun toMarkdown(report: DiagnosticsReport, includeLog: Boolean = true, includeCleanChecks: Boolean = true): String {
        val sb = StringBuilder(16_384)

        sb.append("# ").append(About.APP_NAME).append(" — отчёт диагностики\n\n")
        sb.append("> ").append(badge(report.verdict)).append(" **Вердикт: ")
            .append(report.verdict.title).append("** — ").append(report.verdict.summary).append("  \n")
        sb.append("> Итоговый риск: **").append(report.totalScore).append("/100** · ")
            .append("сработало **").append(report.hits.size).append("** из **")
            .append(report.checksRun).append("** проверок · ").append(secs(report.elapsedMs)).append("  \n")
        sb.append("> Скан: ").append(ts(report.startedAt)).append("\n")
        report.forcedBy?.let {
            sb.append(">\n> ⚠️ Вердикт повышен принудительно: `").append(it).append("`\n")
        }
        sb.append("\n")

        // Устройство
        val d = report.device
        sb.append("## Устройство\n\n")
        sb.append("| Поле | Значение |\n|---|---|\n")
        listOf(
            "Производитель" to (d.manufacturer + " / " + d.brand),
            "Модель" to (d.model + " (" + d.device + ")"),
            "Product / Hardware / Board" to (d.product + " / " + d.hardware + " / " + d.board),
            "Android" to (d.androidRelease + " (API " + d.sdkInt + ")"),
            "Build type / tags" to (d.buildType + " / " + d.buildTags),
            "ABI" to d.abis.joinToString(", "),
            "Fingerprint" to d.fingerprint,
            "Ядро" to d.kernel,
        ).forEach { (k, v) ->
            sb.append("| ").append(cell(k)).append(" | `").append(cell(v)).append("` |\n")
        }
        sb.append("\n")

        // Корзины
        sb.append("## Риск по категориям\n\n")
        sb.append("| Корзина | Риск | Шкала | Сработало |\n|---|---:|---|---:|\n")
        report.buckets.forEach { b ->
            sb.append("| ").append(cell(b.bucket.title))
                .append(" | ").append(b.normalized)
                .append(" | `").append(bar(b.normalized)).append("`")
                .append(" | ").append(b.hits).append(" |\n")
        }
        sb.append("\n")

        // Ключевые находки
        val top = report.topSignals(10)
        sb.append("## Ключевые находки\n\n")
        if (top.isEmpty()) {
            sb.append("_Ни одна проверка не сработала._\n\n")
        } else {
            top.forEachIndexed { i, s ->
                sb.append(i + 1).append(". ").append(mark(s.severity)).append(" **").append(s.title)
                    .append("** · `").append(s.id).append("` · ").append(s.severity.label)
                    .append(" · уверенность ").append(s.confidence).append("% · вклад ")
                    .append(s.score).append("\n")
                sb.append("   - Почему: ").append(s.why).append("\n")
                sb.append("   - Метод: `").append(s.method).append("`\n")
                if (s.evidence.isNotEmpty()) {
                    sb.append("   - Улики:\n")
                    s.evidence.forEach { e ->
                        sb.append("     - `").append(e.key).append("` = `").append(e.value).append("`\n")
                    }
                }
            }
            sb.append("\n")
        }

        // Подробности
        sb.append("## Подробности по проверкам\n\n")
        report.probes.forEach { p -> appendProbe(sb, p, includeCleanChecks) }

        // Лог
        if (includeLog) {
            sb.append("## Полный лог сканирования (").append(report.log.size).append(" строк)\n\n")
            sb.append("<details>\n<summary>Развернуть лог</summary>\n\n")
            sb.append("```text\n")
            report.log.forEach { l ->
                sb.append(logPrefix(l.sinceStartMs, l.level)).append(" [").append(l.tag).append("] ")
                    .append(l.message).append("\n")
                l.detail?.lineSequence()?.forEach { line ->
                    if (line.isNotBlank()) sb.append("        ").append(line).append("\n")
                }
            }
            sb.append("```\n\n</details>\n\n")
        }

        sb.append("---\n\n")
        sb.append("Отчёт собран [").append(About.APP_NAME).append(" v").append(About.VERSION)
            .append("](").append(About.REPO_URL).append(") · автор [").append(About.AUTHOR)
            .append("](").append(About.AUTHOR_URL).append(") · лицензия ").append(About.LICENSE).append("\n")

        return sb.toString()
    }

    private fun appendProbe(sb: StringBuilder, p: ProbeReport, includeClean: Boolean) {
        val status = when {
            p.timedOut -> "⏱ тайм-аут"
            p.error != null -> "❌ ошибка"
            p.hits.isNotEmpty() -> "⚠️ сработало " + p.hits.size
            else -> "✅ чисто"
        }
        sb.append("### ").append(p.displayName).append(" · `").append(p.probeId).append("`\n\n")
        sb.append("Категория: **").append(p.category.title).append("** · корзина: **")
            .append(p.category.bucket.title).append("** · статус: ").append(status)
            .append(" · ").append(secs(p.elapsedMs)).append(" · вклад ").append(p.score).append("\n\n")
        p.error?.let { sb.append("\u003e Ошибка выполнения: `").append(it).append("`\n\n") }

        val shown = if (includeClean) p.signals else p.hits
        if (shown.isEmpty()) {
            sb.append("_Нет данных._\n\n")
            return
        }

        sb.append("| | Проверка | Уровень | Уверенность | Вклад |\n|---|---|---|---:|---:|\n")
        shown.forEach { s ->
            sb.append("| ").append(if (s.triggered) "🔴" else "✅")
                .append(" | ").append(cell(s.title)).append(" · `").append(s.id).append("`")
                .append(" | ").append(s.severity.label)
                .append(" | ").append(s.confidence).append("%")
                .append(" | ").append(s.score).append(" |\n")
        }
        sb.append("\n")

        p.hits.forEach { s -> appendHitDetail(sb, s) }
    }

    private fun appendHitDetail(sb: StringBuilder, s: Signal) {
        sb.append("<details>\n<summary>").append(mark(s.severity)).append(" ").append(s.title)
            .append(" — почему это важно</summary>\n\n")
        sb.append("- **Почему:** ").append(s.why).append("\n")
        sb.append("- **Метод:** `").append(s.method).append("`\n")
        sb.append("- **Вес:** ").append(s.severity.label).append(" (").append(s.severity.weight)
            .append(") · **уверенность:** ").append(s.confidence).append("% · **вклад:** ")
            .append(s.score).append("\n")
        if (s.evidence.isNotEmpty()) {
            sb.append("- **Улики:**\n\n")
            sb.append("  | Ключ | Значение |\n  |---|---|\n")
            s.evidence.forEach { e ->
                sb.append("  | `").append(cell(e.key)).append("` | `").append(cell(e.value)).append("` |\n")
            }
        }
        sb.append("\n</details>\n\n")
    }

    private fun logPrefix(sinceStartMs: Long, level: LogLevel): String {
        val t = String.format(Locale.US, "%7.3f", sinceStartMs / 1000.0)
        return "[" + t + "s] " + level.tag
    }
}
