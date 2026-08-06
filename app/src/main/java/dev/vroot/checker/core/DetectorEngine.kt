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

/** Прогресс сканирования для UI. */
data class ScanProgress(val done: Int, val total: Int, val current: String) {
    val fraction: Float get() = if (total == 0) 0f else done.toFloat() / total.toFloat()
}

/**
 * Движок диагностики.
 *
 * Все пробы выполняются параллельно в [Dispatchers.IO], каждая под своим
 * тайм-аутом и в своём try/catch: одна упавшая проба не роняет скан,
 * а превращается в failed-запись отчёта.
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
            log.info("engine", "Старт диагностики Vroot Checker", buildString {
                append("Проб к выполнению: ").append(probes.size)
                append("\nНативный слой: ").append(if (NativeBridge.available) "загружен (libvroot.so)" else "НЕДОСТУПЕН — часть чеков пропущена")
                append("\nshell разрешён: ").append(config.allowShell)
                append("\nКорзины: ").append(config.enabledBuckets.joinToString { it.title })
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
        log.trace(probe.id, "→ проба «" + probe.displayName + "» запущена")
        var timedOut = false
        var error: String? = null

        val signals: List<Signal> = try {
            withTimeoutOrNull(probe.timeoutMs.coerceAtMost(config.probeTimeoutMs.coerceAtLeast(probe.timeoutMs))) {
                probe.run(ctx)
            } ?: run {
                timedOut = true
                log.warn(probe.id, "Тайм-аут пробы (" + probe.timeoutMs + " мс) — результат не учитывается")
                emptyList()
            }
        } catch (t: Throwable) {
            error = t.javaClass.simpleName + ": " + (t.message ?: "нет описания")
            log.error(probe.id, "Проба упала: " + error)
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
            "← проба завершена за " + elapsed + " мс: срабатываний " + hits + " из " + stamped.size
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

        // Итог — не среднее, а «худшая корзина + затухающий вклад остальных»:
        // один жёсткий root важнее трёх мелких косвенных признаков эмулятора.
        val sorted = buckets.map { it.normalized }.sortedDescending()
        val total = sorted.foldIndexed(0.0) { i, acc, v -> acc + v * (1.0 / (1 shl i)) }
            .toInt().coerceIn(0, 100)

        val hardHit = reports.flatMap { it.signals }
            .firstOrNull { it.triggered && it.severity == Severity.CRITICAL && it.confidence >= 90 }

        val baseVerdict = when {
            total >= 65 -> Verdict.HOSTILE
            total >= 35 -> Verdict.COMPROMISED
            total >= 15 -> Verdict.SUSPICIOUS
            else -> Verdict.CLEAN
        }
        val verdict = if (hardHit != null && baseVerdict.ordinal < Verdict.HOSTILE.ordinal) Verdict.HOSTILE else baseVerdict

        val elapsed = System.currentTimeMillis() - startedAt
        val failed = reports.count { it.failed }

        log.info("engine", "Вердикт: " + verdict.title + " (" + total + "/100)", buildString {
            buckets.forEach { append(it.bucket.title).append(": ").append(it.normalized).append("/100 (срабатываний ").append(it.hits).append(")\n") }
            append("Проверок выполнено: ").append(reports.sumOf { it.signals.size })
            append("\nПроб с ошибкой/тайм-аутом: ").append(failed)
            append("\nВремя: ").append(elapsed).append(" мс")
            if (hardHit != null) append("\nВердикт форсирован критическим сигналом: ").append(hardHit.id)
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
            forcedBy = hardHit?.id,
        )
    }

    /** Мягкое насыщение: 0→0, 55→~50, 150→~85, дальше почти плато. */
    private fun normalize(raw: Int): Int {
        if (raw <= 0) return 0
        val r = raw.toDouble()
        return (100.0 * (1.0 - Math.exp(-r / 70.0))).toInt().coerceIn(0, 100)
    }
}
