package dev.vroot.checker.probes

import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/** Build.* analysis and internal contradictions in the firmware description. */
class BuildFingerprintProbe : BaseProbe() {
    override val id = "virt.build"
    override val displayName = "Build fingerprint"
    override val category = Category.EMULATOR

    /**
     * Tokens that are only meaningful in fields which a real vendor always
     * fills in. Plenty of retail phones ship BOOTLOADER=unknown, and treating
     * that as an emulator marker flagged every second stock device.
     */
    private val placeholderTokens = setOf("unknown", "")
    private val placeholderAllowed = setOf("BOOTLOADER", "RADIO", "SERIAL", "BOARD", "HARDWARE")

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val fields = mapOf(
            "FINGERPRINT" to Build.FINGERPRINT,
            "MODEL" to Build.MODEL,
            "PRODUCT" to Build.PRODUCT,
            "DEVICE" to Build.DEVICE,
            "BOARD" to Build.BOARD,
            "BRAND" to Build.BRAND,
            "HARDWARE" to Build.HARDWARE,
            "MANUFACTURER" to Build.MANUFACTURER,
            "BOOTLOADER" to Build.BOOTLOADER,
        ).mapValues { it.value.orEmpty() }

        val strong = ArrayList<Pair<String, String>>()
        val weak = ArrayList<Pair<String, String>>()
        fields.forEach { (name, value) ->
            Signatures.EMULATOR_BUILD_TOKENS.forEach { token ->
                if (PathTokens.containsToken(value, token)) {
                    val entry = name to (value + "  <- " + token)
                    val isPlaceholder = token.lowercase() in placeholderTokens && name in placeholderAllowed
                    if (isPlaceholder) weak.add(entry) else strong.add(entry)
                }
            }
        }

        out += signal(
            id = "build_tokens",
            title = "Emulator markers in Build.*",
            triggered = strong.isNotEmpty(),
            severity = if (strong.size >= 3) Severity.CRITICAL else Severity.HIGH,
            confidence = if (strong.size >= 3) 95 else 75,
            why = "Emulator Build fields contain telltale words (generic, sdk_gphone, vbox86, ranchu). The more fields match, the less likely it is a coincidence. Placeholder values such as BOOTLOADER=unknown are ignored because retail phones ship them too.",
            method = "android.os.Build",
            evidence = (strong + weak).take(12).map { ev(it.first, it.second) },
        )

        val brand = Build.BRAND.orEmpty().lowercase()
        val manufacturer = Build.MANUFACTURER.orEmpty().lowercase()
        val inconsistent = brand.isNotEmpty() && manufacturer.isNotEmpty() &&
            !Build.FINGERPRINT.orEmpty().lowercase().contains(brand) &&
            !Build.FINGERPRINT.orEmpty().lowercase().contains(manufacturer)
        out += signal(
            id = "fingerprint_inconsistent",
            title = "Fingerprint does not match the brand",
            triggered = inconsistent,
            severity = Severity.MEDIUM,
            confidence = 65,
            why = "On stock firmware the fingerprint always starts with the brand name. A mismatch means Build fields are being spoofed, either by a module or by an emulator posing as a phone.",
            method = "android.os.Build cross-check",
            evidence = listOf(
                ev("BRAND", Build.BRAND),
                ev("MANUFACTURER", Build.MANUFACTURER),
                ev("FINGERPRINT", Build.FINGERPRINT),
            ),
        )

        val propFingerprint = ctx.prop("ro.build.fingerprint")
        out += signal(
            id = "fingerprint_mismatch",
            title = "Build.FINGERPRINT differs from ro.build.fingerprint",
            triggered = propFingerprint.isNotEmpty() && propFingerprint != Build.FINGERPRINT,
            severity = Severity.HIGH,
            confidence = 85,
            why = "The Java field and the system property come from the same source. They only diverge when one of the layers is actively being rewritten.",
            method = "Build vs SystemProperties",
            evidence = listOf(ev("Build", Build.FINGERPRINT), ev("prop", propFingerprint)),
        )

        return out
    }
}
