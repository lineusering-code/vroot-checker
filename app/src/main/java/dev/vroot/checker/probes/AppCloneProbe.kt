package dev.vroot.checker.probes

import android.os.Process
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge

/**
 * Running inside a container (VirtualApp, Parallel Space, Dual Apps, Island).
 * The core idea: in that mode the process physically belongs to another package.
 */
class AppCloneProbe : BaseProbe() {
    override val id = "virt.appclone"
    override val displayName = "Clones and containers"
    override val category = Category.APP_CLONE

    /** System components legitimately share files with every app on the device. */
    private val sharedProviders = listOf(
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.webview",
        "com.google.android.webview",
        "com.google.android.trichromelibrary",
        "com.android.providers.media",
    )

    /** A container maps foreign code, not foreign fonts. */
    private val codeSuffixes = listOf(".so", ".apk", ".jar", ".dex", ".oat", ".odex", ".vdex", ".art")

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val pkg = ctx.selfPackage

        val dataDir = runCatching { ctx.app.applicationInfo.dataDir.orEmpty() }.getOrDefault("")
        out += signal(
            id = "datadir_mismatch",
            title = "dataDir does not match the package name",
            triggered = dataDir.isNotEmpty() && !dataDir.endsWith("/" + pkg),
            severity = Severity.HIGH,
            confidence = 85,
            why = "dataDir is normally /data/user/0/<package>. A path leading into another app's directory means a container launched us.",
            method = "ApplicationInfo.dataDir",
            evidence = listOf(ev("dataDir", dataDir), ev("package", pkg)),
        )

        val uid = Process.myUid()
        out += signal(
            id = "weird_uid",
            title = "Unusual process UID",
            triggered = uid > 999_999 || uid < 10_000,
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Regular apps get a UID in the 10000..19999 range for the first user. A much larger UID means a work profile or clone, a smaller one means a system context.",
            method = "Process.myUid + getuid(JNI)",
            evidence = listOf(ev("uid_java", uid), ev("uid_native", NativeBridge.uid())),
        )

        val foreignPkgRegions = ctx.maps.filter { r ->
            val p = r.path
            (p.startsWith("/data/data/") || p.startsWith("/data/user/")) &&
                !p.contains(pkg) &&
                sharedProviders.none { p.contains(it) } &&
                codeSuffixes.any { p.endsWith(it) }
        }
        out += signal(
            id = "foreign_data_maps",
            title = "Code from another app's data directory is mapped in",
            triggered = foreignPkgRegions.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "Executable code loaded from another package's data directory is how VirtualApp-style containers work. Shared assets such as the Play Services emoji fonts are excluded: every app on the device maps those.",
            method = "procfs: /proc/self/maps",
            evidence = foreignPkgRegions.take(8).map { ev("region", it.path) },
        )

        val cgroup = ctx.selfCgroup
        val cgroupOdd = cgroup.isNotEmpty() && !cgroup.contains("uid_") && !cgroup.contains("apps")
        out += signal(
            id = "cgroup_shape",
            title = "Unusual process cgroup",
            triggered = cgroupOdd,
            severity = Severity.LOW,
            confidence = 55,
            why = "Android places apps in a cgroup whose path contains uid_ or apps. Deviations show up in containers and cloud phones.",
            method = "procfs: /proc/self/cgroup",
            evidence = listOf(ev("cgroup", cgroup.lineSequence().firstOrNull().orEmpty().take(120))),
        )

        val exe = NativeBridge.readlink("/proc/self/exe").orEmpty()
        out += signal(
            id = "exe_path",
            title = "Process was not started by the stock app_process",
            triggered = exe.isNotEmpty() && !exe.contains("app_process"),
            severity = Severity.HIGH,
            confidence = 80,
            why = "Every Android app starts through app_process as a zygote fork. A different executable means a substituted runtime.",
            method = "jni: readlink(/proc/self/exe)",
            evidence = listOf(ev("exe", exe)),
        )

        return out
    }
}
