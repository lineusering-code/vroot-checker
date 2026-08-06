package dev.vroot.checker.probes

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Pkg
import java.io.File
import java.security.MessageDigest

/** Целостность самого приложения: подпись, источник установки, debuggable, чужие .so. */
class AppIntegrityProbe : BaseProbe() {
    override val id = "integrity.app"
    override val displayName = "Целостность приложения"
    override val category = Category.APP_INTEGRITY

    @Suppress("DEPRECATION")
    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val pm = ctx.app.packageManager
        val pkg = ctx.selfPackage
        val appInfo = ctx.app.applicationInfo

        val debuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        out += signal(
            id = "debuggable_flag",
            title = "Сборка помечена как debuggable",
            triggered = debuggable,
            severity = Severity.MEDIUM,
            confidence = 95,
            why = "Флаг debuggable разрешает прицепиться отладчиком и run-as без root. В релизе его быть не должно.",
            method = "ApplicationInfo.flags",
            evidence = listOf(ev("FLAG_DEBUGGABLE", debuggable)),
        )

        val sha = runCatching {
            val sigs: List<Signature> =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                    info.signingInfo?.apkContentsSigners?.filterNotNull().orEmpty()
                } else {
                    pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                        .signatures?.filterNotNull().orEmpty()
                }
            sigs.firstOrNull()?.let { s ->
                MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
                    .joinToString("") { b -> "%02X".format(b) }
            }.orEmpty()
        }.getOrDefault("")
        val expected = ctx.config.expectedSigningSha256
        out += signal(
            id = "signature",
            title = "Подпись APK не совпадает с эталонной",
            triggered = expected != null && !sha.equals(expected, ignoreCase = true),
            severity = Severity.CRITICAL,
            confidence = 100,
            why = "Если слепок сертификата отличается от ожидаемого — APK был распакован, изменён и подписан заново.",
            method = "PackageManager signing certificates",
            evidence = listOf(ev("sha256", sha.ifEmpty { "неизвестно" }), ev("expected", expected ?: "не задана")),
        )

        val installer = Pkg.installerOf(ctx.app, pkg)
        val trusted = setOf(
            "com.android.vending", "com.google.android.feedback",
            "com.amazon.venezia", "com.huawei.appmarket", "com.sec.android.app.samsungapps",
        )
        out += signal(
            id = "installer",
            title = "Установлено не из доверенного магазина",
            triggered = installer == null || installer !in trusted,
            severity = Severity.INFO,
            confidence = 60,
            why = "Пустой installer значит установку через adb или файловый менеджер. Для диагностической утилиты это норма, поэтому вес минимальный.",
            method = "PackageManager installer",
            evidence = listOf(ev("installer", installer ?: "нет")),
        )

        val libDir = appInfo.nativeLibraryDir.orEmpty()
        val libs = runCatching { File(libDir).listFiles()?.map { it.name }.orEmpty() }.getOrDefault(emptyList())
        val known = setOf("libvroot.so")
        val foreign = libs.filter { it !in known && !it.startsWith("libc++") }
        out += signal(
            id = "foreign_native_libs",
            title = "Лишние .so в каталоге библиотек приложения",
            triggered = foreign.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 75,
            why = "В нашем APK только одна нативная библиотека. Любая другая рядом — след переупаковки или инжекта gadget.",
            method = "nativeLibraryDir listing",
            evidence = foreign.take(8).map { ev("lib", it) },
        )

        val sourceDir = appInfo.sourceDir.orEmpty()
        out += signal(
            id = "apk_location",
            title = "APK лежит вне /data/app",
            triggered = sourceDir.isNotEmpty() && !sourceDir.startsWith("/data/app"),
            severity = Severity.HIGH,
            confidence = 80,
            why = "Штатно установленные приложения живут в /data/app. Другой путь бывает у контейнеров и предустановленных подмен.",
            method = "ApplicationInfo.sourceDir",
            evidence = listOf(ev("sourceDir", sourceDir)),
        )

        return out
    }
}
