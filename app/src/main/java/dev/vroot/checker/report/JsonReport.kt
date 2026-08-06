package dev.vroot.checker.report

import dev.vroot.checker.About
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
 * Машиночитаемый отчёт. Содержит АБСОЛЮТНО всё: отпечаток устройства,
 * каждую проверку (включая чистые), объяснение «почему», улики и полный лог.
 */
object JsonReport {

    const val SCHEMA_VERSION = 1

    private fun iso(ts: Long): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US)
        fmt.timeZone = TimeZone.getDefault()
        return fmt.format(Date(ts))
    }

    fun toJson(report: DiagnosticsReport, includeLog: Boolean = true, pretty: Boolean = true): String {
        val root = JSONObject()

        root.put("schema", SCHEMA_VERSION)
        root.put("generatedAt", iso(System.currentTimeMillis()))
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
                        .put("title", report.verdict.title)
                        .put("summary", report.verdict.summary),
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
                    .put("title", b.bucket.title)
                    .put("raw", b.raw)
                    .put("normalized", b.normalized)
                    .put("hits", b.hits),
            )
        }
        root.put("buckets", buckets)

        val probes = JSONArray()
        report.probes.forEach { probes.put(probeJson(it)) }
        root.put("probes", probes)

        val top = JSONArray()
        report.topSignals(10).forEach { top.put(signalJson(it)) }
        root.put("topSignals", top)

        if (includeLog) {
            val log = JSONArray()
            report.log.forEach { log.put(logJson(it)) }
            root.put("log", log)
        }

        return if (pretty) root.toString(2) else root.toString()
    }

    private fun probeJson(p: ProbeReport): JSONObject {
        val signals = JSONArray()
        p.signals.forEach { signals.put(signalJson(it)) }
        return JSONObject()
            .put("id", p.probeId)
            .put("name", p.displayName)
            .put("category", p.category.name)
            .put("categoryTitle", p.category.title)
            .put("bucket", p.category.bucket.name)
            .put("elapsedMs", p.elapsedMs)
            .put("timedOut", p.timedOut)
            .put("error", p.error ?: JSONObject.NULL)
            .put("score", p.score)
            .put("hitCount", p.hits.size)
            .put("signals", signals)
    }

    private fun signalJson(s: Signal): JSONObject {
        val evidence = JSONArray()
        s.evidence.forEach { e ->
            evidence.put(JSONObject().put("key", e.key).put("value", e.value))
        }
        return JSONObject()
            .put("id", s.id)
            .put("title", s.title)
            .put("category", s.category.name)
            .put("bucket", s.bucket.name)
            .put("severity", s.severity.label)
            .put("weight", s.severity.weight)
            .put("confidence", s.confidence)
            .put("triggered", s.triggered)
            .put("score", s.score)
            .put("why", s.why)
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
