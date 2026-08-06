package dev.vroot.checker.probes

import android.os.Build
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal

/** Анализ Build.* и внутренних противоречий прошивки. */
class BuildFingerprintProbe : BaseProbe() {
    override val id = "virt.build"
    override val displayName = "Отпечаток сборки"
    override val category = Category.EMULATOR

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

        val hits = ArrayList<Pair<String, String>>()
        fields.forEach { (name, value) ->
            Signatures.EMULATOR_BUILD_TOKENS.forEach { token ->
                if (value.contains(token, ignoreCase = true)) hits.add(name to (value + "  ← " + token))
            }
        }

        out += signal(
            id = "build_tokens",
            title = "Маркеры эмулятора в Build.*",
            triggered = hits.isNotEmpty(),
            severity = if (hits.size >= 3) Severity.CRITICAL else Severity.HIGH,
            confidence = if (hits.size >= 3) 95 else 75,
            why = "Поля Build у эмуляторов содержат характерные слова (generic, sdk_gphone, vbox86, ranchu и т.д.). Чем больше полей совпало, тем меньше шанс случайности.",
            method = "android.os.Build",
            evidence = hits.take(12).map { ev(it.first, it.second) },
        )

        val brand = Build.BRAND.orEmpty().lowercase()
        val manufacturer = Build.MANUFACTURER.orEmpty().lowercase()
        val inconsistent = brand.isNotEmpty() && manufacturer.isNotEmpty() &&
            !Build.FINGERPRINT.orEmpty().lowercase().contains(brand) &&
            !Build.FINGERPRINT.orEmpty().lowercase().contains(manufacturer)
        out += signal(
            id = "fingerprint_inconsistent",
            title = "Fingerprint не бьётся с брендом",
            triggered = inconsistent,
            severity = Severity.MEDIUM,
            confidence = 65,
            why = "У стоковой прошивки fingerprint всегда начинается с имени бренда. Расхождение — признак подмены Build-полей (spoofing-модуль или эмулятор, маскирующийся под телефон).",
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
            title = "Build.FINGERPRINT не равен ro.build.fingerprint",
            triggered = propFingerprint.isNotEmpty() && propFingerprint != Build.FINGERPRINT,
            severity = Severity.HIGH,
            confidence = 85,
            why = "Java-поле и системное свойство читаются из одного источника. Расхождение бывает только при активной подмене одного из уровней.",
            method = "Build vs SystemProperties",
            evidence = listOf(ev("Build", Build.FINGERPRINT), ev("prop", propFingerprint)),
        )

        return out
    }
}
