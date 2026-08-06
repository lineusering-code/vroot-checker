package dev.vroot.checker.core.util

/** Значение системного property, прочитанное разными каналами. */
data class PropValue(
    val key: String,
    val reflect: String,
    val native: String,
    val shell: String?,
) {
    val value: String get() = reflect.ifEmpty { native.ifEmpty { shell ?: "" } }

    /** Расхождение каналов = кто-то подменяет getprop (resetprop / hook). */
    val mismatch: Boolean
        get() {
            val values = listOfNotNull(
                reflect.takeIf { it.isNotEmpty() },
                native.takeIf { it.isNotEmpty() },
                shell?.takeIf { it.isNotEmpty() },
            )
            return values.distinct().size > 1
        }

    fun describe(): String = "reflect='" + reflect + "' jni='" + native + "' shell='" + (shell ?: "-") + "'"
}

object Props {

    private val cache = HashMap<String, String>()

    private val systemProperties: Class<*>? by lazy {
        runCatching { Class.forName("android.os.SystemProperties") }.getOrNull()
    }

    fun get(key: String): String = synchronized(cache) {
        cache.getOrPut(key) { readReflect(key).ifEmpty { NativeBridge.getProp(key) } }
    }

    fun readReflect(key: String): String = try {
        val m = systemProperties?.getMethod("get", String::class.java)
        (m?.invoke(null, key) as? String).orEmpty()
    } catch (t: Throwable) {
        ""
    }

    /** Читает property всеми доступными каналами (для детекта подмены). */
    fun multi(key: String, allowShell: Boolean): PropValue = PropValue(
        key = key,
        reflect = readReflect(key),
        native = NativeBridge.getProp(key),
        shell = if (allowShell) Shell.exec(arrayOf("getprop", key), 700).stdout.trim() else null,
    )

    fun boolProp(key: String): Boolean = get(key).let { it == "1" || it.equals("true", true) }
}
