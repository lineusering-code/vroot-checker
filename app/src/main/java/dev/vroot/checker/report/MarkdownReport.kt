package dev.vroot.checker.report

import dev.vroot.checker.About
import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.core.i18n.UiStrings
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.core.model.LogLevel
import dev.vroot.checker.core.model.ProbeReport
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.model.Verdict
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Human-readable Markdown report - suitable for an issue, a chat message or an
 * .md file.
 *
 * The language is passed in rather than read from a global, so the export can
 * be produced in a language the device is not currently running in.
 */
object MarkdownReport {

    private fun ts(at: Long): String =
        SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.US).format(Date(at))

    private fun secs(ms: Long, s: UiStrings): String =
        String.format(Locale.US, "%.2f", ms / 1000.0) + " " + s.secondsShort

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

    fun toMarkdown(
        report: DiagnosticsReport,
        lang: Lang = Lang.DEFAULT,
        includeLog: Boolean = true,
        includeCleanChecks: Boolean = true,
    ): String {
        val s = Tr.strings(lang)
        val sb = StringBuilder(16_384)

        sb.append("# ").append(About.APP_NAME).append(" — ").append(s.reportTitleSuffix).append("\n\n")
        sb.append("> ").append(badge(report.verdict)).append(" **").append(s.verdict).append(": ")
            .append(Tr.verdictTitle(lang, report.verdict)).append("** — ")
            .append(Tr.verdictSummary(lang, report.verdict)).append("  \n")
        sb.append("> ").append(s.overallRisk).append(": **").append(report.totalScore).append("/100** · ")
            .append(String.format(Locale.US, s.checksTriggered, report.hits.size, report.checksRun))
            .append(" · ").append(secs(report.elapsedMs, s)).append("  \n")
        sb.append("> ").append(s.scanStarted).append(": ").append(ts(report.startedAt)).append("\n")
        report.forcedBy?.let {
            sb.append(">\n> ⚠️ ").append(s.forcedUp).append(": `").append(it).append("`\n")
        }
        sb.append("\n")

        // Device
        val d = report.device
        sb.append("## ").append(s.device).append("\n\n")
        sb.append("| ").append(s.colField).append(" | ").append(s.colValue).append(" |\n|---|---|\n")
        listOf(
            s.devManufacturer to (d.manufacturer + " / " + d.brand),
            s.devModel to (d.model + " (" + d.device + ")"),
            s.devProductHwBoard to (d.product + " / " + d.hardware + " / " + d.board),
            s.devAndroid to (d.androidRelease + " (API " + d.sdkInt + ")"),
            s.devBuildTypeTags to (d.buildType + " / " + d.buildTags),
            s.devAbi to d.abis.joinToString(", "),
            s.devFingerprint to d.fingerprint,
            s.devKernel to d.kernel,
        ).forEach { (k, v) ->
            sb.append("| ").append(cell(k)).append(" | `").append(cell(v)).append("` |\n")
        }
        sb.append("\n")

        // Buckets
        sb.append("## ").append(s.riskByCategory).append("\n\n")
        sb.append("| ").append(s.colBucket).append(" | ").append(s.colRisk).append(" | ")
            .append(s.colScale).append(" | ").append(s.colHits).append(" |\n|---|---:|---|---:|\n")
        report.buckets.forEach { b ->
            sb.append("| ").append(cell(Tr.bucket(lang, b.bucket)))
                .append(" | ").append(b.normalized)
                .append(" | `").append(bar(b.normalized)).append("`")
                .append(" | ").append(b.hits).append(" |\n")
        }
        sb.append("\n")

        // Key findings
        val top = report.topSignals(10)
        sb.append("## ").append(s.keyFindings).append("\n\n")
        if (top.isEmpty()) {
            sb.append("_").append(s.nothingTriggered).append("_\n\n")
        } else {
            top.forEachIndexed { i, sig ->
                sb.append(i + 1).append(". ").append(mark(sig.severity)).append(" **")
                    .append(Tr.signalTitle(lang, sig.id, sig.title))
                    .append("** · `").append(sig.id).append("` · ").append(Tr.severity(lang, sig.severity))
                    .append(" · ").append(s.confidence).append(" ").append(sig.confidence)
                    .append("% · ").append(s.contribution).append(" ").append(sig.score).append("\n")
                sb.append("   - ").append(s.why).append(": ")
                    .append(Tr.signalWhy(lang, sig.id, sig.why)).append("\n")
                sb.append("   - ").append(s.method).append(": `").append(sig.method).append("`\n")
                if (sig.evidence.isNotEmpty()) {
                    sb.append("   - ").append(s.evidence).append(":\n")
                    sig.evidence.forEach { e ->
                        sb.append("     - `").append(e.key).append("` = `").append(e.value).append("`\n")
                    }
                }
            }
            sb.append("\n")
        }

        // Per-probe detail
        sb.append("## ").append(s.perCheckDetails).append("\n\n")
        report.probes.forEach { p -> appendProbe(sb, p, lang, s, includeCleanChecks) }

        // Log
        if (includeLog) {
            sb.append("## ").append(s.fullLog).append(" (").append(report.log.size).append(")\n\n")
            sb.append("<details>\n<summary>").append(s.expandLog).append("</summary>\n\n")
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
        sb.append(s.footerBuiltWith).append(" [").append(About.APP_NAME).append(" v").append(About.VERSION)
            .append("](").append(About.REPO_URL).append(") · ").append(s.footerAuthor).append(" [")
            .append(About.AUTHOR).append("](").append(About.AUTHOR_URL).append(") · ")
            .append(s.footerLicense).append(" ").append(About.LICENSE).append("\n")

        return sb.toString()
    }

    private fun appendProbe(
        sb: StringBuilder,
        p: ProbeReport,
        lang: Lang,
        s: UiStrings,
        includeClean: Boolean,
    ) {
        val status = when {
            p.timedOut -> "⏱ " + s.statusTimeout
            p.error != null -> "❌ " + s.statusError
            p.hits.isNotEmpty() -> "⚠️ " + String.format(Locale.US, s.statusTriggered, p.hits.size)
            else -> "✅ " + s.statusClean
        }
        sb.append("### ").append(Tr.probe(lang, p.probeId, p.displayName))
            .append(" · `").append(p.probeId).append("`\n\n")
        sb.append(s.category).append(": **").append(Tr.category(lang, p.category)).append("** · ")
            .append(s.bucket).append(": **").append(Tr.bucket(lang, p.category.bucket))
            .append("** · ").append(s.status).append(": ").append(status)
            .append(" · ").append(secs(p.elapsedMs, s)).append(" · ").append(s.contribution)
            .append(" ").append(p.score).append("\n\n")
        p.error?.let {
            sb.append("> ").append(s.executionError).append(": `").append(it).append("`\n\n")
        }

        val shown = if (includeClean) p.signals else p.hits
        if (shown.isEmpty()) {
            sb.append("_").append(s.noData).append("_\n\n")
            return
        }

        sb.append("| | ").append(s.colCheck).append(" | ").append(s.colLevel).append(" | ")
            .append(s.confidence).append(" | ").append(s.contribution)
            .append(" |\n|---|---|---|---:|---:|\n")
        shown.forEach { sig ->
            sb.append("| ").append(if (sig.triggered) "🔴" else "✅")
                .append(" | ").append(cell(Tr.signalTitle(lang, sig.id, sig.title)))
                .append(" · `").append(sig.id).append("`")
                .append(" | ").append(Tr.severity(lang, sig.severity))
                .append(" | ").append(sig.confidence).append("%")
                .append(" | ").append(sig.score).append(" |\n")
        }
        sb.append("\n")

        p.hits.forEach { sig -> appendHitDetail(sb, sig, lang, s) }
    }

    private fun appendHitDetail(sb: StringBuilder, sig: Signal, lang: Lang, s: UiStrings) {
        sb.append("<details>\n<summary>").append(mark(sig.severity)).append(" ")
            .append(Tr.signalTitle(lang, sig.id, sig.title))
            .append(" — ").append(s.whyItMatters).append("</summary>\n\n")
        sb.append("- **").append(s.why).append(":** ")
            .append(Tr.signalWhy(lang, sig.id, sig.why)).append("\n")
        sb.append("- **").append(s.method).append(":** `").append(sig.method).append("`\n")
        sb.append("- **").append(s.weight).append(":** ").append(Tr.severity(lang, sig.severity))
            .append(" (").append(sig.severity.weight).append(") · **").append(s.confidence)
            .append(":** ").append(sig.confidence).append("% · **").append(s.contribution)
            .append(":** ").append(sig.score).append("\n")
        if (sig.evidence.isNotEmpty()) {
            sb.append("- **").append(s.evidence).append(":**\n\n")
            sb.append("  | ").append(s.colKey).append(" | ").append(s.colValue)
                .append(" |\n  |---|---|\n")
            sig.evidence.forEach { e ->
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
