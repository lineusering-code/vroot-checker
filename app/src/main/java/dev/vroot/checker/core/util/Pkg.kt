package dev.vroot.checker.core.util

import android.content.Context
import android.content.pm.PackageManager

object Pkg {

    fun installedPackages(ctx: Context): Set<String> = try {
        ctx.packageManager.getInstalledPackages(0).mapNotNull { it.packageName }.toSet()
    } catch (t: Throwable) {
        emptySet()
    }

    /**
     * Проверка наличия пакета тремя каналами: список, getPackageInfo и
     * getApplicationInfo. Скрывалки обычно патчат только первый.
     */
    fun isInstalled(ctx: Context, pkg: String, cachedList: Set<String>): PkgProbe {
        val pm = ctx.packageManager
        val inList = cachedList.contains(pkg)
        val byInfo = runCatching { pm.getPackageInfo(pkg, 0); true }.getOrDefault(false)
        val byApp = runCatching { pm.getApplicationInfo(pkg, 0); true }.getOrDefault(false)
        return PkgProbe(pkg, inList, byInfo, byApp)
    }

    fun installerOf(ctx: Context, pkg: String): String? = try {
        val pm: PackageManager = ctx.packageManager
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg)
        }
    } catch (t: Throwable) {
        null
    }
}

data class PkgProbe(
    val pkg: String,
    val inList: Boolean,
    val byPackageInfo: Boolean,
    val byApplicationInfo: Boolean,
) {
    val present: Boolean get() = inList || byPackageInfo || byApplicationInfo

    /** Пакет виден одним каналом и невидим другим — значит его прячут. */
    val hidden: Boolean get() = present && !(inList && byPackageInfo && byApplicationInfo)

    fun describe(): String = "list=" + inList + " pkgInfo=" + byPackageInfo + " appInfo=" + byApplicationInfo
}
