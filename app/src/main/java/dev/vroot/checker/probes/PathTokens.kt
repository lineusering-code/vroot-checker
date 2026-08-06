package dev.vroot.checker.probes

/**
 * Boundary-aware token matching for paths and class names.
 *
 * Plain `contains()` is unusable here. On a stock device it produces:
 *   "ksu" -> /system/lib64/libvndksupport.so   (libv-NDKSU-pport)
 *   "su"  -> /system/lib64/libvndksupport.so   (libvndk-SU-pport)
 * Both looked like a rooted phone. A token only counts when it is not glued
 * to other alphanumerics, with one exception: a leading "lib" is allowed so
 * that libzygisk.so still matches the token "zygisk".
 */
object PathTokens {

    /** Read-only partitions. Root and hook frameworks never load from here. */
    private val SYSTEM_PREFIXES = listOf(
        "/system/", "/system_ext/", "/apex/", "/vendor/", "/product/", "/odm/",
    )

    fun isSystemPath(path: String): Boolean = SYSTEM_PREFIXES.any { path.startsWith(it) }

    fun containsToken(haystack: String, token: String): Boolean {
        if (token.isEmpty()) return false
        val h = haystack.lowercase()
        val t = token.lowercase()
        var from = 0
        while (from <= h.length - t.length) {
            val i = h.indexOf(t, from)
            if (i < 0) return false
            if (boundaryOk(h, i, t.length)) return true
            from = i + 1
        }
        return false
    }

    fun anyToken(haystack: String, tokens: Collection<String>): Boolean =
        tokens.any { containsToken(haystack, it) }

    /** A token hit that is also outside the read-only partitions. */
    fun suspiciousPath(path: String, tokens: Collection<String>): Boolean =
        !isSystemPath(path) && anyToken(path, tokens)

    private fun boundaryOk(h: String, index: Int, length: Int): Boolean {
        val end = index + length
        val endOk = end >= h.length || !h[end].isLetterOrDigit()
        if (!endOk) return false
        if (index == 0 || !h[index - 1].isLetterOrDigit()) return true
        // allow the conventional "lib" prefix: libzygisk.so, libriru.so
        return index >= 3 &&
            h.regionMatches(index - 3, "lib", 0, 3) &&
            (index == 3 || !h[index - 4].isLetterOrDigit())
    }
}
