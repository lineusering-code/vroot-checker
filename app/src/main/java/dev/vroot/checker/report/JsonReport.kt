package dev.vroot.checker.report

import dev.vroot.checker.About
import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.core.model.LogLine
import dev.vroot.checker.core.model.ProbeReport
import dev.vroot.checker.core.model.Signal
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Machine-readable report. It contains absolutely everything: the device
 * fingerprint, every check (clean ones included), the "why", the evidence and
 * the full log.
 *
 * Human-readable text follows the selected language, but every translated
 * field sits next to a stable code (`verdict.code`, `severityCode`,
 * `category`, `bucket`). Tooling should key off the codes: they never change
 * with the language, while titles do.
 */
object JsonReport {

    const val SCHEMA_VERSION = 2

    private fun iso(ts: Long): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US)
        fmt.timeZone = TimeZone.getDefault()
        return fmt.format(Date(ts))
    }

    fun toJson(
        report: DiagnosticsReport,
        lang: Lang = Lang.DEFAULT,
        includeLog: Boolean = true,
        pretty: Boolean = true,
    ): String {
        val root = JSONObject()

        root.put("schema", SCHEMA_VERSION)
        root.put("generatedAt", iso(System.currentTimeMillis()))
        root.put("language", lang.code)
        root.put(
            "tool",
            JSONObject()
                .put("name", About.APP_NAME)
                .put("version", About.VERSION)
                .put("author", About.AUTHOR)
                .put("authorUrl", About.AUTHOR_URL)
                .put("repository", About.REPO_URL)
                .put("license", About.LICENSE),
        )

        root.put(
            "scan",
            JSONObject()
                .put("startedAt", report.startedAt)
                .put("startedAtIso", iso(report.startedAt))
                .put("elapsedMs", report.elapsedMs)
                .put("checksRun", report.checksRun)
                .put("hitCount", report.hits.size)
                .put("totalScore", report.totalScore)
                .put("forcedBy", report.forcedBy ?: JSONObject.NULL)
                .put(
                    "verdict",
                    JSONObject()
                        .put("code", report.verdict.name)
                        .put("title", Tr.verdictTitle(lang, report.verdict))
                        .put("summary", Tr.verdictSummary(lang, report.verdict)),
                ),
        )

        val d = report.device
        root.put(
            "device",
            JSONObject()
                .put("manufacturer", d.manufacturer)
                .put("brand", d.brand)
                .put("model", d.model)
                .put("device", d.device)
                .put("product", d.product)
                .put("hardware", d.hardware)
                .put("board", d.board)
                .put("fingerprint", d.fingerprint)
                .put("buildTags", d.buildTags)
                .put("buildType", d.buildType)
                .put("androidRelease", d.androidRelease)
                .put("sdkInt", d.sdkInt)
                .put("abis", JSONArray(d.abis))
                .put("kernel", d.kernel),
        )

        val buckets = JSONArray()
        report.buckets.forEach { b ->
            buckets.put(
                JSONObject()
                    .put("bucket", b.bucket.name)
                    .put("title", Tr.bucket(lang, b.bucket))
                    .put("raw", b.raw)
                    .put("normalized", b.normalized)
                    .put("hits", b.hits),
            )
        }
        root.put("buckets", buckets)

        val probes = JSONArray()
        report.probes.forEach { probes.put(probeJson(it, lang)) }
        root.put("probes", probes)

        val top = JSONArray()
        report.topSignals(10).forEach { top.put(signalJson(it, lang)) }
        root.put("topSignals", top)

        if (includeLog) {
            val log = JSONArray()
            report.log.forEach { log.put(logJson(it)) }
            root.put("log", log)
        }

        return if (pretty) root.toString(2) else root.toString()
    }

    private fun probeJson(p: ProbeReport, lang: Lang): JSONObject {
        val signals = JSONArray()
        p.signals.forEach { signals.put(signalJson(it, lang)) }
        return JSONObject()
            .put("id", p.probeId)
            // Kept as explicit aliases: report readers and jq snippets in the
            // README address these by name.
            .put("probeId", p.probeId)
            .put("name", Tr.probe(lang, p.probeId, p.displayName))
            .put("displayName", Tr.probe(lang, p.probeId, p.displayName))
            .put("category", p.category.name)
            .put("categoryTitle", Tr.category(lang, p.category))
            .put("bucket", p.category.bucket.name)
            .put("bucketTitle", Tr.bucket(lang, p.category.bucket))
            .put("elapsedMs", p.elapsedMs)
            .put("timedOut", p.timedOut)
            .put("error", p.error ?: JSONObject.NULL)
            .put("score", p.score)
            .put("hitCount", p.hits.size)
            .put("signals", signals)
    }

    private fun signalJson(s: Signal, lang: Lang): JSONObject {
        val evidence = JSONArray()
        s.evidence.forEach { e ->
            evidence.put(JSONObject().put("key", e.key).put("value", e.value))
        }
        return JSONObject()
            .put("id", s.id)
            .put("title", Tr.signalTitle(lang, s.id, s.title))
            .put("category", s.category.name)
            .put("bucket", s.bucket.name)
            .put("severityCode", s.severity.name)
            .put("severity", Tr.severity(lang, s.severity))
            .put("weight", s.severity.weight)
            .put("confidence", s.confidence)
            .put("triggered", s.triggered)
            .put("score", s.score)
            .put("why", Tr.signalWhy(lang, s.id, s.why))
            .put("method", s.method)
            .put("elapsedMs", s.elapsedMs)
            .put("evidence", evidence)
    }

    private fun logJson(l: LogLine): JSONObject = JSONObject()
        .put("at", l.at)
        .put("atIso", iso(l.at))
        .put("sinceStartMs", l.sinceStartMs)
        .put("level", l.level.name)
        .put("tag", l.tag)
        .put("message", l.message)
        .put("detail", l.detail ?: JSONObject.NULL)
}
