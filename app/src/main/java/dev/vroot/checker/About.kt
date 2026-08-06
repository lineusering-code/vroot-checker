package dev.vroot.checker

import dev.vroot.checker.core.i18n.Lang
import dev.vroot.checker.core.i18n.Tr

/** Single place for project links and metadata, shared by the UI and the exports. */
object About {
    const val APP_NAME = "Vroot Checker"
    const val VERSION = "1.0.0"
    const val TAGLINE = "Hard diagnostics for root, virtual environments and hooking"

    const val AUTHOR = "lineusering-code"
    const val AUTHOR_URL = "https://github.com/lineusering-code"

    const val REPO_NAME = "lineusering-code/vroot-checker"
    const val REPO_URL = "https://github.com/lineusering-code/vroot-checker"
    const val ISSUES_URL = "https://github.com/lineusering-code/vroot-checker/issues"
    const val RELEASES_URL = "https://github.com/lineusering-code/vroot-checker/releases"
    const val LICENSE = "MIT"

    /**
     * Signature attached to every export. Takes a language because a report can
     * be rendered in a language the device is not running in.
     */
    fun exportFooter(lang: Lang = Lang.DEFAULT): String {
        val s = Tr.strings(lang)
        return APP_NAME + " v" + VERSION + " \u2014 " + REPO_URL +
            " (" + s.footerAuthor + ": " + AUTHOR + ", " + s.footerLicense + ": " + LICENSE + ")"
    }

    /** Kept for callers that render outside of a language context. */
    val exportFooterDefault: String get() = exportFooter()
}
