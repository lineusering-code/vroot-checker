package dev.vroot.checker.core.model

/**
 * Weight of a signal in the final risk score.
 *
 * The label is a stable machine code, never translated: it appears in JSON
 * exports and in the log, where it has to stay greppable.
 */
enum class Severity(val weight: Int, val label: String) {
    INFO(0, "INFO"),
    LOW(8, "LOW"),
    MEDIUM(18, "MEDIUM"),
    HIGH(32, "HIGH"),
    CRITICAL(55, "CRITICAL"),
}

/** Top-level scoring buckets; the dashboard summary is built from these. */
enum class Bucket(val title: String) {
    ROOT("Root"),
    VIRTUAL("Virtual"),
    HOOK("Hooking"),
    INTEGRITY("Integrity"),
}

/**
 * Signal category.
 *
 * [title] is the English base text. Translations are resolved at render time
 * through the i18n layer, keyed by the enum name, so no display string is ever
 * hardcoded in a single language again.
 *
 * [icon] is the name of a vector drawable in res/drawable, letting the UI draw
 * a consistent icon set without a manual mapping table.
 */
enum class Category(val bucket: Bucket, val title: String, val icon: String) {
    ROOT_BINARIES(Bucket.ROOT, "Root binaries", "ic_terminal"),
    ROOT_MANAGER(Bucket.ROOT, "Root managers", "ic_shield_alert"),
    MOUNTS(Bucket.ROOT, "Mount points", "ic_storage"),
    SYSTEM_PROPS(Bucket.ROOT, "System properties", "ic_tune"),
    SELINUX(Bucket.ROOT, "SELinux", "ic_policy"),
    PACKAGES(Bucket.ROOT, "Installed packages", "ic_apps"),
    EMULATOR(Bucket.VIRTUAL, "Emulator", "ic_desktop"),
    HYPERVISOR(Bucket.VIRTUAL, "Hypervisor", "ic_layers"),
    HARDWARE(Bucket.VIRTUAL, "Hardware and sensors", "ic_memory"),
    APP_CLONE(Bucket.VIRTUAL, "Clones and containers", "ic_copy"),
    HOOK_FRAMEWORK(Bucket.HOOK, "Hooking frameworks", "ic_bug"),
    DYNAMIC_ANALYSIS(Bucket.HOOK, "Dynamic analysis", "ic_search"),
    DEBUG(Bucket.HOOK, "Debugging and ADB", "ic_debug"),
    APP_INTEGRITY(Bucket.INTEGRITY, "Application integrity", "ic_verified"),
}

/** A single piece of evidence: exactly what was found. */
data class Evidence(val key: String, val value: String)

/**
 * The atomic result of one check.
 *
 * @param id stable dotted identifier, also the translation key.
 * @param why human-readable explanation of WHY this counts as a sign.
 * @param method which channel was used (java / shell / jni / procfs). This
 *               matters because a disagreement between channels is itself
 *               evidence.
 * @param confidence 0..100, how sure we are that this is not a false positive.
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

/** Result of one probe: its signals plus execution telemetry. */
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

/**
 * [title] is a stable machine code and is deliberately not translated.
 * [summary] is the English base text; translations come from the i18n layer.
 */
enum class Verdict(val title: String, val summary: String) {
    CLEAN("CLEAN", "No signs of tampering found"),
    SUSPICIOUS("SUSPICIOUS", "A few individually weak signs are present"),
    COMPROMISED("COMPROMISED", "The environment is almost certainly modified"),
    HOSTILE("HOSTILE", "Something is actively interfering with the app"),
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
