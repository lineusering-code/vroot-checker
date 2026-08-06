package dev.vroot.checker.ui.theme

import androidx.compose.ui.graphics.Color
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Verdict

// Базовая палитра — спокойный технический сине-стальной тон.
val BlueSteel10 = Color(0xFF001B3D)
val BlueSteel20 = Color(0xFF002F63)
val BlueSteel30 = Color(0xFF00458C)
val BlueSteel40 = Color(0xFF005CB8)
val BlueSteel80 = Color(0xFFA9C7FF)
val BlueSteel90 = Color(0xFFD6E3FF)

val Slate10 = Color(0xFF0F1417)
val Slate20 = Color(0xFF1A2024)
val Slate30 = Color(0xFF2A3136)
val Slate90 = Color(0xFFE1E3E5)

// Семантика вердикта и уровней — одни и те же цвета везде в UI.
val VerdictClean = Color(0xFF2E7D32)
val VerdictCleanContainer = Color(0xFFB7F0BB)
val VerdictSuspicious = Color(0xFFB08800)
val VerdictSuspiciousContainer = Color(0xFFFFE7A3)
val VerdictCompromised = Color(0xFFD35400)
val VerdictCompromisedContainer = Color(0xFFFFDBC7)
val VerdictHostile = Color(0xFFC62828)
val VerdictHostileContainer = Color(0xFFFFDAD6)

val SeverityInfo = Color(0xFF5C6BC0)
val SeverityLow = Color(0xFF8D9440)
val SeverityMedium = Color(0xFFB08800)
val SeverityHigh = Color(0xFFD35400)
val SeverityCritical = Color(0xFFC62828)

fun Verdict.accent(): Color = when (this) {
    Verdict.CLEAN -> VerdictClean
    Verdict.SUSPICIOUS -> VerdictSuspicious
    Verdict.COMPROMISED -> VerdictCompromised
    Verdict.HOSTILE -> VerdictHostile
}

fun Verdict.container(): Color = when (this) {
    Verdict.CLEAN -> VerdictCleanContainer
    Verdict.SUSPICIOUS -> VerdictSuspiciousContainer
    Verdict.COMPROMISED -> VerdictCompromisedContainer
    Verdict.HOSTILE -> VerdictHostileContainer
}

fun Severity.accent(): Color = when (this) {
    Severity.INFO -> SeverityInfo
    Severity.LOW -> SeverityLow
    Severity.MEDIUM -> SeverityMedium
    Severity.HIGH -> SeverityHigh
    Severity.CRITICAL -> SeverityCritical
}
