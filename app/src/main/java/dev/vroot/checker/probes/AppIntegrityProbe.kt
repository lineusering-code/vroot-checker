package dev.vroot.checker.probes

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import dev.vroot.checker.BuildConfig
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Pkg
import java.io.File
import java.security.MessageDigest

/** Integrity of this app itself: signature, install source, debuggable, foreign .so files. */
class AppIntegrityProbe : BaseProbe() {
    override val id = "integrity.app"
    override val displayName = "Application integrity"
    override val category = Category.APP_INTEGRITY

    @Suppress("DEPRECATION")
    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val pm = ctx.app.packageManager
        val pkg = ctx.selfPackage
        val appInfo = ctx.app.applicationInfo

        // A debug build is debuggable on purpose. Only report it as a finding
        // when a release build somehow carries the flag.
        val debuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val unexpectedDebuggable = debuggable && !BuildConfig.DEBUG
        out += signal(
            id = "debuggable_flag",
            title = "Release build carries the debuggable flag",
            triggered = unexpectedDebuggable,
            severity = Severity.MEDIUM,
            confidence = 95,
            why = "FLAG_DEBUGGABLE lets anyone attach a debugger and use run-as without root. A release APK must never have it. This debug build is expected to.",
            method = "ApplicationInfo.flags + BuildConfig.DEBUG",
            evidence = listOf(ev("FLAG_DEBUGGABLE", debuggable), ev("BuildConfig.DEBUG", BuildConfig.DEBUG)),
        )

        val sha = runCatching {
            val sigs: List<Signature> =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                        .signingInfo?.apkContentsSigners?.filterNotNull().orEmpty()
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
            title = "APK signature does not match the expected one",
            triggered = expected != null && !sha.equals(expected, ignoreCase = true),
            severity = Severity.CRITICAL,
            confidence = 100,
            why = "If the certificate digest differs from the expected value, the APK was unpacked, modified and re-signed.",
            method = "PackageManager signing certificates",
            evidence = listOf(ev("sha256", sha.ifEmpty { "unknown" }), ev("expected", expected ?: "not configured")),
        )

        val installer = Pkg.installerOf(ctx.app, pkg)
        val trusted = setOf(
            "com.android.vending", "com.google.android.feedback",
            "com.amazon.venezia", "com.huawei.appmarket", "com.sec.android.app.samsungapps",
        )
        out += signal(
            id = "installer",
            title = "Not installed from a trusted store",
            triggered = installer == null || installer !in trusted,
            severity = Severity.INFO,
            confidence = 60,
            why = "An empty installer means adb or a file manager. For a diagnostics utility that is normal, hence the minimal weight.",
            method = "PackageManager installer",
            evidence = listOf(ev("installer", installer ?: "none")),
        )

        val libDir = appInfo.nativeLibraryDir.orEmpty()
        val libs = runCatching { File(libDir).listFiles()?.map { it.name }.orEmpty() }.getOrDefault(emptyList())
        val known = setOf("libvroot.so")
        val foreign = libs.filter { it !in known && !it.startsWith("libc++") }
        out += signal(
            id = "foreign_native_libs",
            title = "Extra .so files in the app library directory",
            triggered = foreign.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 75,
            why = "Our APK ships exactly one native library. Anything next to it is a trace of repackaging or a gadget injection.",
            method = "nativeLibraryDir listing",
            evidence = foreign.take(8).map { ev("lib", it) },
        )

        val sourceDir = appInfo.sourceDir.orEmpty()
        out += signal(
            id = "apk_location",
            title = "APK lives outside /data/app",
            triggered = sourceDir.isNotEmpty() && !sourceDir.startsWith("/data/app"),
            severity = Severity.HIGH,
            confidence = 80,
            why = "Normally installed apps live in /data/app. A different path is typical for containers and pre-installed replacements.",
            method = "ApplicationInfo.sourceDir",
            evidence = listOf(ev("sourceDir", sourceDir)),
        )

        return out
    }
}
