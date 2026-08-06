package dev.vroot.checker

/** Единое место для ссылок и метаданных проекта: используется и в UI, и в экспорте. */
object About {
    const val APP_NAME = "Vroot Checker"
    const val VERSION = "1.0.0"
    const val TAGLINE = "Жёсткая диагностика root, виртуальной среды и перехватов"

    const val AUTHOR = "lineusering-code"
    const val AUTHOR_URL = "https://github.com/lineusering-code"

    const val REPO_NAME = "lineusering-code/vroot-checker"
    const val REPO_URL = "https://github.com/lineusering-code/vroot-checker"
    const val ISSUES_URL = "https://github.com/lineusering-code/vroot-checker/issues"
    const val RELEASES_URL = "https://github.com/lineusering-code/vroot-checker/releases"
    const val LICENSE = "MIT"

    /** Подпись, которая уезжает вместе с любым экспортом. */
    val exportFooter: String
        get() = APP_NAME + " v" + VERSION + " — " + REPO_URL + " (автор: " + AUTHOR + ")"
}
