package dev.vroot.checker.core.i18n

import dev.vroot.checker.core.model.Bucket
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Verdict

/**
 * Single entry point for translated text.
 *
 * Enum display text is translated here rather than being stored in the enums,
 * because an enum constant is a process-wide singleton and cannot hold a value
 * that depends on the currently selected language.
 *
 * Signal titles and explanations are authored in English inside the probes and
 * overridden here for other languages. That keeps the probe code readable as
 * plain security logic and confines translation churn to the i18n package.
 */
object Tr {

    fun strings(lang: Lang): UiStrings = when (lang) {
        Lang.EN -> UiStrings.EN
        Lang.RU -> RU_STRINGS
    }

    fun bucket(lang: Lang, b: Bucket): String = when (lang) {
        Lang.EN -> b.title
        Lang.RU -> when (b) {
            Bucket.ROOT -> "Root"
            Bucket.VIRTUAL -> "Виртуализация"
            Bucket.HOOK -> "Хуки"
            Bucket.INTEGRITY -> "Целостность"
        }
    }

    fun category(lang: Lang, c: Category): String = when (lang) {
        Lang.EN -> c.title
        Lang.RU -> when (c) {
            Category.ROOT_BINARIES -> "Root-бинарники"
            Category.ROOT_MANAGER -> "Root-менеджеры"
            Category.MOUNTS -> "Точки монтирования"
            Category.SYSTEM_PROPS -> "Системные свойства"
            Category.SELINUX -> "SELinux"
            Category.PACKAGES -> "Установленные пакеты"
            Category.EMULATOR -> "Эмулятор"
            Category.HYPERVISOR -> "Гипервизор"
            Category.HARDWARE -> "Железо и сенсоры"
            Category.APP_CLONE -> "Клоны и контейнеры"
            Category.HOOK_FRAMEWORK -> "Хук-фреймворки"
            Category.DYNAMIC_ANALYSIS -> "Динамический анализ"
            Category.DEBUG -> "Отладка и ADB"
            Category.APP_INTEGRITY -> "Целостность приложения"
        }
    }

    fun verdictSummary(lang: Lang, v: Verdict): String = when (lang) {
        Lang.EN -> v.summary
        Lang.RU -> when (v) {
            Verdict.CLEAN -> "Признаков вмешательства не найдено"
            Verdict.SUSPICIOUS -> "Есть отдельные слабые признаки"
            Verdict.COMPROMISED -> "Среда почти наверняка модифицирована"
            Verdict.HOSTILE -> "Что-то активно вмешивается в работу приложения"
        }
    }

    /** Probe display name, keyed by probe id. Falls back to the English name. */
    fun probe(lang: Lang, probeId: String, fallback: String): String =
        if (lang == Lang.EN) fallback else RU_PROBES[probeId] ?: fallback

    /** Signal title, keyed by the full dotted signal id. */
    fun signalTitle(lang: Lang, signalId: String, fallback: String): String =
        if (lang == Lang.EN) fallback else RU_SIGNAL_TITLES[signalId] ?: fallback

    /** Signal explanation, keyed by the full dotted signal id. */
    fun signalWhy(lang: Lang, signalId: String, fallback: String): String =
        if (lang == Lang.EN) fallback else RU_SIGNAL_WHY[signalId] ?: fallback
}
