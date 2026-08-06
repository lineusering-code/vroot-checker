package dev.vroot.checker.core

import android.content.Context
import android.os.Build
import dev.vroot.checker.core.model.Bucket
import dev.vroot.checker.core.model.DeviceFingerprint
import dev.vroot.checker.core.model.ScanLog
import dev.vroot.checker.core.util.MapRegion
import dev.vroot.checker.core.util.Pkg
import dev.vroot.checker.core.util.ProcMaps
import dev.vroot.checker.core.util.Props
import dev.vroot.checker.core.util.Sys

data class EngineConfig(
    /** Default per-probe timeout. */
    val probeTimeoutMs: Long = 1800L,
    /** Allow exec(): some checks get stronger, but slower and more visible. */
    val allowShell: Boolean = true,
    /** Which buckets to run. */
    val enabledBuckets: Set<Bucket> = Bucket.entries.toSet(),
    /**
     * Probe ids the user switched off.
     *
     * These are removed before the scan starts, not filtered out of the
     * results: a disabled check costs no time and cannot influence the score.
     */
    val disabledProbes: Set<String> = emptySet(),
    /** Log clean checks too, not just the hits. */
    val logCleanChecks: Boolean = true,
    /** Expected APK signing SHA-256 (lowercase hex) for the integrity check. */
    val expectedSigningSha256: String? = null,
)

/**
 * Shared scan context: expensive sources (/proc, the package list) are read
 * once and reused by every probe.
 */
class ProbeContext(
    val app: Context,
    val log: ScanLog,
    val config: EngineConfig,
) {
    val selfPackage: String = app.packageName

    val mounts: List<String> by lazy { Sys.readLines("/proc/mounts") }
    val mountInfo: List<String> by lazy { Sys.readLines("/proc/self/mountinfo") }
    val maps: List<MapRegion> by lazy { ProcMaps.readSelf() }
    val cpuinfo: String by lazy { Sys.readText("/proc/cpuinfo") }
    val selfStatus: String by lazy { Sys.readText("/proc/self/status") }
    val selfCgroup: String by lazy { Sys.readText("/proc/self/cgroup") }
    val ttyDrivers: String by lazy { Sys.readText("/proc/tty/drivers") }
    val unixSockets: String by lazy { Sys.readText("/proc/net/unix") }
    val tcpSockets: String by lazy { Sys.readText("/proc/net/tcp") + Sys.readText("/proc/net/tcp6") }
    val installedPackages: Set<String> by lazy { Pkg.installedPackages(app) }

    fun prop(key: String): String = Props.get(key)

    fun fingerprint(): DeviceFingerprint = DeviceFingerprint(
        manufacturer = Build.MANUFACTURER,
        brand = Build.BRAND,
        model = Build.MODEL,
        device = Build.DEVICE,
        product = Build.PRODUCT,
        hardware = Build.HARDWARE,
        board = Build.BOARD,
        fingerprint = Build.FINGERPRINT,
        buildTags = Build.TAGS ?: "",
        buildType = Build.TYPE ?: "",
        androidRelease = Build.VERSION.RELEASE ?: "",
        sdkInt = Build.VERSION.SDK_INT,
        abis = Build.SUPPORTED_ABIS?.toList() ?: emptyList(),
        kernel = Sys.readText("/proc/version").trim(),
    )
}
