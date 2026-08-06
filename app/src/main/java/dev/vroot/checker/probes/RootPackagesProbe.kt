package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Pkg

/** Известные root/hook/clone-пакеты + детект пакетов, которые прячутся. */
class RootPackagesProbe : BaseProbe() {
    override val id = "root.packages"
    override val displayName = "Установленные пакеты"
    override val category = Category.PACKAGES
    override val timeoutMs = 3000L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val installed = ctx.installedPackages

        val rootProbes = Signatures.ROOT_PACKAGES.map { Pkg.isInstalled(ctx.app, it, installed) }
        val rootFound = rootProbes.filter { it.present }
        out += signal(
            id = "root_apps",
            title = "Установлены root-приложения",
            triggered = rootFound.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "Magisk Manager, SuperSU, LSPosed, Shizuku и подобные приложения ставятся только на модифицированные устройства.",
            method = "PackageManager (3 канала)",
            evidence = rootFound.map { ev(it.pkg, it.describe()) },
        )

        val hidden = rootProbes.filter { it.hidden }
        out += signal(
            id = "hidden_packages",
            title = "Пакет виден не всеми каналами",
            triggered = hidden.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 85,
            why = "getInstalledPackages не показывает пакет, а getPackageInfo его находит (или наоборот). Так работают скрывалки списка приложений.",
            method = "cross-check PackageManager API",
            evidence = hidden.map { ev(it.pkg, it.describe()) },
        )

        val clones = Signatures.CLONE_PACKAGES
            .map { Pkg.isInstalled(ctx.app, it, installed) }.filter { it.present }
        out += signal(
            id = "clone_apps",
            title = "Установлены клонеры приложений",
            triggered = clones.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 75,
            why = "Parallel Space, VirtualApp, App Cloner и аналоги умеют запускать чужое приложение внутри своего процесса и полностью контролировать его окружение.",
            method = "PackageManager",
            evidence = clones.map { ev(it.pkg, it.describe()) },
        )

        val emus = Signatures.EMULATOR_PACKAGES
            .map { Pkg.isInstalled(ctx.app, it, installed) }.filter { it.present }
        out += signal(
            id = "emulator_apps",
            title = "Служебные пакеты эмуляторов",
            triggered = emus.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "BlueStacks, Nox, LDPlayer, MEmu и облачные телефоны ставят свои фирменные пакеты в системный образ.",
            method = "PackageManager",
            evidence = emus.map { ev(it.pkg, it.describe()) },
        )

        return out
    }
}
