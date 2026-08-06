package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Pkg

/** Known root/hook/clone packages plus detection of packages that hide themselves. */
class RootPackagesProbe : BaseProbe() {
    override val id = "root.packages"
    override val displayName = "Installed packages"
    override val category = Category.PACKAGES
    override val timeoutMs = 3000L

    /**
     * Privileged helpers that do NOT require root: Shizuku starts its service
     * over ADB on a fully stock device. Reporting it as a root app was the
     * single loudest false positive on clean phones.
     */
    private val adbCapable = setOf(
        "moe.shizuku.privileged.api",
        "moe.shizuku.manager",
        "rikka.shizuku",
        "com.rosan.dhizuku",
    )

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val installed = ctx.installedPackages

        val rootProbes = Signatures.ROOT_PACKAGES.map { Pkg.isInstalled(ctx.app, it, installed) }
        val present = rootProbes.filter { it.present }
        val (adbHelpers, rootFound) = present.partition { it.pkg in adbCapable }

        out += signal(
            id = "root_apps",
            title = "Root manager apps are installed",
            triggered = rootFound.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "Magisk Manager, SuperSU, LSPosed and friends only get installed on modified devices.",
            method = "PackageManager (3 channels)",
            evidence = rootFound.map { ev(it.pkg, it.describe()) },
        )

        out += signal(
            id = "adb_privileged_helper",
            title = "ADB-based privileged helper installed",
            triggered = adbHelpers.isNotEmpty(),
            severity = Severity.INFO,
            confidence = 70,
            why = "Shizuku and similar tools grant elevated APIs to other apps, but they run over ADB and work on completely stock devices. Worth knowing about, not evidence of root.",
            method = "PackageManager",
            evidence = adbHelpers.map { ev(it.pkg, it.describe()) },
        )

        val hidden = rootProbes.filter { it.hidden }
        out += signal(
            id = "hidden_packages",
            title = "Package is visible to some PackageManager channels only",
            triggered = hidden.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "getInstalledPackages does not list the package while getPackageInfo finds it, or the other way round. That is how app-list hiding modules work.",
            method = "cross-check PackageManager API",
            evidence = hidden.map { ev(it.pkg, it.describe()) },
        )

        val clones = Signatures.CLONE_PACKAGES
            .map { Pkg.isInstalled(ctx.app, it, installed) }.filter { it.present }
        out += signal(
            id = "clone_apps",
            title = "App cloning tools are installed",
            triggered = clones.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 75,
            why = "Parallel Space, VirtualApp, App Cloner and similar tools can run another app inside their own process and fully control its environment.",
            method = "PackageManager",
            evidence = clones.map { ev(it.pkg, it.describe()) },
        )

        val emus = Signatures.EMULATOR_PACKAGES
            .map { Pkg.isInstalled(ctx.app, it, installed) }.filter { it.present }
        out += signal(
            id = "emulator_apps",
            title = "Emulator service packages",
            triggered = emus.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "BlueStacks, Nox, LDPlayer, MEmu and cloud phones bake their own branded packages into the system image.",
            method = "PackageManager",
            evidence = emus.map { ev(it.pkg, it.describe()) },
        )

        return out
    }
}
