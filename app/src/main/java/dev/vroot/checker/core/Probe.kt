package dev.vroot.checker.core

import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Evidence
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/**
 * Одна изолированная проба. Не должна бросать наружу — движок это переживёт,
 * но проба обязана сама аккуратно обрабатывать отсутствие доступа к файлам.
 */
interface Probe {
    val id: String
    val displayName: String
    val category: Category

    /** Персональный тайм-аут; медленным пробам (shell) стоит поднимать. */
    val timeoutMs: Long get() = 1500L

    suspend fun run(ctx: ProbeContext): List<Signal>
}

/** Хелперы конструирования сигналов, чтобы пробы читались как декларации. */
abstract class BaseProbe : Probe {

    protected fun signal(
        id: String,
        title: String,
        triggered: Boolean,
        severity: Severity,
        why: String,
        method: String,
        confidence: Int = 100,
        evidence: List<Evidence> = emptyList(),
    ) = Signal(
        id = this.id + "." + id,
        title = title,
        category = category,
        severity = severity,
        triggered = triggered,
        why = why,
        method = method,
        confidence = confidence,
        evidence = evidence,
    )

    protected fun ev(key: String, value: String?) = Evidence(key, value ?: "<null>")

    protected fun ev(key: String, value: Boolean) = Evidence(key, value.toString())

    protected fun ev(key: String, value: Int) = Evidence(key, value.toString())
}
