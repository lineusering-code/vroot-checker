package dev.vroot.checker.probes

import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Props

/**
 * System properties: build mode, verified boot state, and properties that were
 * rewritten at runtime. Each property is read through several channels so a
 * resetprop-style override shows up as a disagreement rather than as a value we
 * simply trust.
 */
class PropsProbe : BaseProbe() {
    override val id = "root.props"
    override val displayName = "System properties and verified boot"
    override val category = Category.SYSTEM_PROPS
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val debuggable = ctx.prop("ro.debuggable")
        val secure = ctx.prop("ro.secure")
        out += signal(
            id = "insecure_build",
            title = "Insecure build (ro.debuggable / ro.secure)",
            triggered = debuggable == "1" || secure == "0",
            severity = Severity.HIGH,
            confidence = 90,
            why = "A retail build always reports ro.debuggable=0 and ro.secure=1. Anything else is an eng/userdebug build or overridden properties, and adb root is available.",
            method = "SystemProperties + __system_property_get",
            evidence = listOf(ev("ro.debuggable", debuggable), ev("ro.secure", secure)),
        )

        val tags = Build.TAGS.orEmpty()
        val type = Build.TYPE.orEmpty()
        out += signal(
            id = "test_keys",
            title = "Build signed with test-keys",
            triggered = tags.contains("test-keys") || type == "userdebug" || type == "eng",
            severity = Severity.MEDIUM,
            confidence = 85,
            why = "Official firmware is signed with release-keys. test-keys means a custom or debug build.",
            method = "android.os.Build",
            evidence = listOf(ev("Build.TAGS", tags), ev("Build.TYPE", type)),
        )

        val vbState = ctx.prop("ro.boot.verifiedbootstate")
        val locked = ctx.prop("ro.boot.flash.locked")
        val verity = ctx.prop("ro.boot.veritymode")
        val bootloaderUnlocked = (vbState.isNotEmpty() && vbState != "green") ||
            locked == "0" || verity.equals("disabled", true)
        out += signal(
            id = "verified_boot",
            title = "Verified Boot is not green",
            triggered = bootloaderUnlocked,
            severity = Severity.HIGH,
            confidence = 88,
            why = "An orange or yellow verified boot state, or dm-verity switched off, means an unlocked bootloader. Persistent root is close to impossible without one.",
            method = "SystemProperties (ro.boot.*)",
            evidence = listOf(
                ev("ro.boot.verifiedbootstate", vbState),
                ev("ro.boot.flash.locked", locked),
                ev("ro.boot.veritymode", verity),
            ),
        )

        val watched = listOf(
            "ro.debuggable", "ro.secure", "ro.build.tags", "ro.build.type",
            "ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.build.fingerprint",
        )
        val mismatched = watched.map { Props.multi(it, ctx.config.allowShell) }.filter { it.mismatch }
        out += signal(
            id = "resetprop_mismatch",
            title = "Property values differ between channels",
            triggered = mismatched.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 92,
            why = "The same property reads differently through SystemProperties, the native API and getprop. That is what masking looks like (resetprop or a hook on property reads).",
            method = "cross-check reflect vs jni vs shell",
            evidence = mismatched.map { ev(it.key, it.describe()) },
        )

        val dangerous = mapOf(
            "service.adb.root" to "1",
            "ro.adb.secure" to "0",
            "persist.sys.root_access" to "3",
            "persist.service.adb.enable" to "1",
        ).filter { (k, v) -> ctx.prop(k) == v }
        out += signal(
            id = "dangerous_props",
            title = "Dangerous property values",
            triggered = dangerous.isNotEmpty(),
            severity = Severity.MEDIUM,
            confidence = 80,
            why = "These properties explicitly permit root access or an insecure adb.",
            method = "SystemProperties",
            evidence = dangerous.map { ev(it.key, it.value) },
        )

        return out
    }
}
