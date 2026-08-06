package dev.vroot.checker.core.i18n

import android.content.Context
import java.util.Locale

/**
 * Languages the app can render in.
 *
 * This is deliberately separate from Android resource qualifiers. A report can
 * be exported in a language that differs from the device locale, and the user
 * can switch the language without restarting the process, so the choice has to
 * live in normal application state rather than in the resource configuration.
 */
enum class Lang(val code: String, val nativeName: String, val englishName: String) {
    EN("en", "English", "English"),
    RU("ru", "\u0420\u0443\u0441\u0441\u043a\u0438\u0439", "Russian");

    companion object {
        val DEFAULT = EN

        fun fromCode(code: String?): Lang =
            entries.firstOrNull { it.code.equals(code, ignoreCase = true) } ?: DEFAULT

        /** English is the fallback for every locale we do not translate. */
        fun fromDeviceLocale(locale: Locale = Locale.getDefault()): Lang =
            entries.firstOrNull { it.code.equals(locale.language, ignoreCase = true) } ?: DEFAULT
    }
}

/**
 * Persisted user preferences.
 *
 * Kept intentionally tiny: SharedPreferences is more than enough for a language
 * code and a set of disabled check ids, and it avoids pulling DataStore and its
 * coroutine plumbing into a process that must start fast.
 */
class AppSettings(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences("vroot_settings", Context.MODE_PRIVATE)

    var lang: Lang
        get() {
            val stored = prefs.getString(KEY_LANG, null)
            // First launch follows the device locale, afterwards the explicit choice wins.
            return if (stored == null) Lang.fromDeviceLocale() else Lang.fromCode(stored)
        }
        set(value) {
            prefs.edit().putString(KEY_LANG, value.code).apply()
        }

    /**
     * Ids of checks the user switched off. Storing the disabled set rather than
     * the enabled one means new probes shipped in a future version are enabled
     * by default instead of silently missing.
     */
    var disabledProbes: Set<String>
        get() = prefs.getStringSet(KEY_DISABLED_PROBES, emptySet())?.toSet().orEmpty()
        set(value) {
            prefs.edit().putStringSet(KEY_DISABLED_PROBES, value).apply()
        }

    fun setProbeEnabled(probeId: String, enabled: Boolean) {
        disabledProbes = if (enabled) disabledProbes - probeId else disabledProbes + probeId
    }

    fun isProbeEnabled(probeId: String): Boolean = probeId !in disabledProbes

    fun resetProbes() {
        disabledProbes = emptySet()
    }

    private companion object {
        const val KEY_LANG = "lang"
        const val KEY_DISABLED_PROBES = "disabled_probes"
    }
}
