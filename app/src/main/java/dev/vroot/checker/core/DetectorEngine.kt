package dev.vroot.checker.core

import android.content.Context
import dev.vroot.checker.core.model.Bucket
import dev.vroot.checker.core.model.BucketScore
import dev.vroot.checker.core.model.DiagnosticsReport
import dev.vroot.checker.core.model.ProbeReport
import dev.vroot.checker.core.model.ScanLog
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.model.Verdict
import dev.vroot.checker.core.util.NativeBridge
import dev.vroot.checker.probes.ProbeCatalog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicInteger

/** Scan progress for the UI. */
data class ScanProgress(val done: Int, val total: Int, val current: String) {
    val fraction: Float get() = if (total == 0) 0f else done.toFloat() / total.toFloat()
}

/**
 * The diagnostics engine.
 *
 * Every probe runs in parallel on [Dispatchers.IO], each with its own timeout
 * and its own try/catch, so one broken probe degrades into a failed report
 * entry instead of taking the whole scan down.
 */
class DetectorEngine(
    private val app: Context,
    private val config: EngineConfig = EngineConfig(),
) {

    suspend fun scan(onProgress: ((ScanProgress) -> Unit)? = null): DiagnosticsReport =
        withContext(Dispatchers.IO) {
            val startedAt = System.currentTimeMillis()
            val log = ScanLog(startedAt)
            val ctx = ProbeContext(app, log, config)

            val probes = ProbeCatalog.all().filter { it.category.bucket in config.enabledBuckets }
            log.info("engine", "Vroot Checker diagnostics started", buildString {
                append("Probes queued: ").append(probes.size)
                append("\nNative layer: ").append(
                    if (NativeBridge.available) "loaded (libvroot.so)" else "UNAVAILABLE - some checks are skipped"
                )
                append("\nShell allowed: ").append(config.allowShell)
                append("\nBuckets: ").append(config.enabledBuckets.joinToString { it.title })
            })

            val done = AtomicInteger(0)
            val reports = coroutineScope {
                probes.map { probe ->
                    async {
                        val report = runProbe(probe, ctx, log)
                        onProgress?.invoke(
                            ScanProgress(done.incrementAndGet(), probes.size, probe.displayName)
                        )
                        report
                    }
                }.awaitAll()
            }.sortedWith(compareBy({ it.category.bucket.ordinal }, { it.probeId }))

            buildReport(ctx, log, reports, startedAt)
        }

    private suspend fun runProbe(probe: Probe, ctx: ProbeContext, log: ScanLog): ProbeReport {
        val t0 = System.currentTimeMillis()
        log.trace(probe.id, "-> probe \"" + probe.displayName + "\" started")
        var timedOut = false
        var error: String? = null

        val signals: List<Signal> = try {
            withTimeoutOrNull(probe.timeoutMs.coerceAtMost(config.probeTimeoutMs.coerceAtLeast(probe.timeoutMs))) {
                probe.run(ctx)
            } ?: run {
                timedOut = true
                log.warn(probe.id, "Probe timed out after " + probe.timeoutMs + " ms - result discarded")
                emptyList()
            }
        } catch (t: Throwable) {
            error = t.javaClass.simpleName + ": " + (t.message ?: "no description")
            log.error(probe.id, "Probe crashed: " + error)
            emptyList()
        }

        val elapsed = System.currentTimeMillis() - t0
        val stamped = signals.map { it.copy(elapsedMs = elapsed) }

        stamped.forEach { s ->
            if (s.triggered || ctx.config.logCleanChecks) log.signal(probe.id, s)
        }

        val hits = stamped.count { it.triggered }
        log.trace(
            probe.id,
            "<- probe finished in " + elapsed + " ms: " + hits + " of " + stamped.size + " checks triggered"
        )

        return ProbeReport(
            probeId = probe.id,
            displayName = probe.displayName,
            category = probe.category,
            signals = stamped,
            elapsedMs = elapsed,
            timedOut = timedOut,
            error = error,
        )
    }

    private fun buildReport(
        ctx: ProbeContext,
        log: ScanLog,
        reports: List<ProbeReport>,
        startedAt: Long,
    ): DiagnosticsReport {
        val buckets = Bucket.entries.map { b ->
            val signals = reports.filter { it.category.bucket == b }.flatMap { it.signals }
            val raw = signals.sumOf { it.score }
            BucketScore(
                bucket = b,
                raw = raw,
                normalized = normalize(raw),
                hits = signals.count { it.triggered },
            )
        }

        // The total is not an average but "worst bucket plus a decaying share of
        // the rest": one hard root finding outweighs three weak emulator hints.
        val sorted = buckets.map { it.normalized }.sortedDescending()
        val total = sorted.foldIndexed(0.0) { i, acc, v -> acc + v * (1.0 / (1 shl i)) }
            .toInt().coerceIn(0, 100)

        val baseVerdict = when {
            total >= 65 -> Verdict.HOSTILE
            total >= 35 -> Verdict.COMPROMISED
            total >= 15 -> Verdict.SUSPICIOUS
            else -> Verdict.CLEAN
        }

        // A single CRITICAL signal is not allowed to override the score on its
        // own: one false positive would then be enough to condemn a clean
        // device. Overriding requires either two independent critical findings
        // or one critical finding on top of an already elevated score.
        val hardHits = reports.flatMap { it.signals }
            .filter { it.triggered && it.severity == Severity.CRITICAL && it.confidence >= 90 }
        val hardProbes = hardHits.map { it.id.substringBeforeLast('.') }.distinct()
        val corroborated = (hardHits.size >= 2 && hardProbes.size >= 2) ||
            (hardHits.isNotEmpty() && total >= 35)

        val forcedBy = if (corroborated && baseVerdict.ordinal < Verdict.HOSTILE.ordinal) {
            hardHits.joinToString(", ") { it.id }
        } else {
            null
        }
        val verdict = if (forcedBy != null) Verdict.HOSTILE else baseVerdict

        val elapsed = System.currentTimeMillis() - startedAt
        val failed = reports.count { it.failed }

        log.info("engine", "Verdict: " + verdict.title + " (" + total + "/100)", buildString {
            buckets.forEach {
                append(it.bucket.title).append(": ").append(it.normalized)
                    .append("/100 (").append(it.hits).append(" hits)\n")
            }
            append("Checks performed: ").append(reports.sumOf { it.signals.size })
            append("\nProbes failed or timed out: ").append(failed)
            append("\nElapsed: ").append(elapsed).append(" ms")
            if (hardHits.isNotEmpty()) {
                append("\nCritical findings: ").append(hardHits.joinToString { it.id })
                append("\nVerdict forced: ").append(if (forcedBy != null) "yes" else "no, not corroborated")
            }
        })

        return DiagnosticsReport(
            verdict = verdict,
            totalScore = total,
            buckets = buckets,
            probes = reports,
            device = ctx.fingerprint(),
            startedAt = startedAt,
            elapsedMs = elapsed,
            log = log.snapshot(),
            forcedBy = forcedBy,
        )
    }

    /** Soft saturation: 0->0, 55->~50, 150->~85, near-plateau beyond that. */
    private fun normalize(raw: Int): Int {
        if (raw <= 0) return 0
        val r = raw.toDouble()
        return (100.0 * (1.0 - Math.exp(-r / 70.0))).toInt().coerceIn(0, 100)
    }
}
