package dev.vroot.checker.core.model

/** Вес сигнала в итоговой оценке риска. */
enum class Severity(val weight: Int, val label: String) {
    INFO(0, "INFO"),
    LOW(8, "LOW"),
    MEDIUM(18, "MEDIUM"),
    HIGH(32, "HIGH"),
    CRITICAL(55, "CRITICAL"),
}

/** Крупные корзины скоринга — по ним строится сводка на дашборде. */
enum class Bucket(val title: String) {
    ROOT("Root"),
    VIRTUAL("Virtual"),
    HOOK("Hooking"),
    INTEGRITY("Integrity"),
}

/**
 * Категория сигнала. [icon] — имя vector drawable в res/drawable,
 * чтобы UI мог рисовать единый набор иконок без ручного маппинга.
 */
enum class Category(val bucket: Bucket, val title: String, val icon: String) {
    ROOT_BINARIES(Bucket.ROOT, "Root-бинарники", "ic_terminal"),
    ROOT_MANAGER(Bucket.ROOT, "Root-менеджеры", "ic_shield_alert"),
    MOUNTS(Bucket.ROOT, "Монтирование", "ic_storage"),
    SYSTEM_PROPS(Bucket.ROOT, "Системные свойства", "ic_tune"),
    SELINUX(Bucket.ROOT, "SELinux", "ic_policy"),
    PACKAGES(Bucket.ROOT, "Установленные пакеты", "ic_apps"),
    EMULATOR(Bucket.VIRTUAL, "Эмулятор", "ic_desktop"),
    HYPERVISOR(Bucket.VIRTUAL, "Гипервизор", "ic_layers"),
    HARDWARE(Bucket.VIRTUAL, "Железо и сенсоры", "ic_memory"),
    APP_CLONE(Bucket.VIRTUAL, "Клоны и контейнеры", "ic_copy"),
    HOOK_FRAMEWORK(Bucket.HOOK, "Хук-фреймворки", "ic_bug"),
    DYNAMIC_ANALYSIS(Bucket.HOOK, "Динамический анализ", "ic_search"),
    DEBUG(Bucket.HOOK, "Отладка и ADB", "ic_debug"),
    APP_INTEGRITY(Bucket.INTEGRITY, "Целостность приложения", "ic_verified"),
}

/** Одна улика: «что именно нашли». */
data class Evidence(val key: String, val value: String)

/**
 * Атомарный результат одной проверки.
 *
 * @param why человекочитаемое объяснение, ПОЧЕМУ это считается признаком.
 * @param method каким каналом проверяли (java / shell / jni / procfs …) —
 *               важно, потому что расхождение каналов само по себе улика.
 * @param confidence 0..100, насколько мы уверены, что это не ложняк.
 */
data class Signal(
    val id: String,
    val title: String,
    val category: Category,
    val severity: Severity,
    val triggered: Boolean,
    val why: String,
    val method: String,
    val confidence: Int = 100,
    val evidence: List<Evidence> = emptyList(),
    val elapsedMs: Long = 0L,
) {
    val score: Int get() = if (triggered) severity.weight * confidence / 100 else 0
    val bucket: Bucket get() = category.bucket
}

/** Результат одной пробы (набор сигналов + телеметрия выполнения). */
data class ProbeReport(
    val probeId: String,
    val displayName: String,
    val category: Category,
    val signals: List<Signal>,
    val elapsedMs: Long,
    val timedOut: Boolean = false,
    val error: String? = null,
) {
    val hits: List<Signal> get() = signals.filter { it.triggered }
    val score: Int get() = signals.sumOf { it.score }
    val failed: Boolean get() = timedOut || error != null
}

enum class Verdict(val title: String, val summary: String) {
    CLEAN("CLEAN", "Признаков вмешательства не найдено"),
    SUSPICIOUS("SUSPICIOUS", "Есть отдельные подозрительные признаки"),
    COMPROMISED("COMPROMISED", "Среда почти наверняка модифицирована"),
    HOSTILE("HOSTILE", "Активное вмешательство в работу приложения"),
}

data class DeviceFingerprint(
    val manufacturer: String,
    val brand: String,
    val model: String,
    val device: String,
    val product: String,
    val hardware: String,
    val board: String,
    val fingerprint: String,
    val buildTags: String,
    val buildType: String,
    val androidRelease: String,
    val sdkInt: Int,
    val abis: List<String>,
    val kernel: String,
)

data class BucketScore(val bucket: Bucket, val raw: Int, val normalized: Int, val hits: Int)

data class DiagnosticsReport(
    val verdict: Verdict,
    val totalScore: Int,
    val buckets: List<BucketScore>,
    val probes: List<ProbeReport>,
    val device: DeviceFingerprint,
    val startedAt: Long,
    val elapsedMs: Long,
    val log: List<LogLine>,
    val forcedBy: String? = null,
) {
    val allSignals: List<Signal> get() = probes.flatMap { it.signals }
    val hits: List<Signal> get() = allSignals.filter { it.triggered }
    val checksRun: Int get() = allSignals.size

    fun bucket(b: Bucket): BucketScore =
        buckets.firstOrNull { it.bucket == b } ?: BucketScore(b, 0, 0, 0)

    fun topSignals(n: Int): List<Signal> =
        hits.sortedWith(compareByDescending<Signal> { it.score }.thenBy { it.id }).take(n)
}
