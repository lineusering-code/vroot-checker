package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge
import dev.vroot.checker.core.util.Sys
import java.io.File

/** Frida: файлы сервера, порты, библиотеки в памяти и характерные потоки. */
class FridaProbe : BaseProbe() {
    override val id = "hook.frida"
    override val displayName = "Frida и динамическая инструментация"
    override val category = Category.DYNAMIC_ANALYSIS
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val files = Sys.probeAll(Signatures.FRIDA_PATHS).filter { it.exists }
        out += signal(
            id = "server_files",
            title = "Файлы frida-server / gadget на диске",
            triggered = files.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "frida-server обычно кладут в /data/local/tmp. Сам факт наличия говорит, что устройство готовили к реверсу.",
            method = "java.io.File + faccessat(JNI)",
            evidence = files.map { ev(it.path, it.describe()) },
        )

        val mapsHits = ctx.maps.filter { r ->
            val p = r.path.lowercase()
            p.contains("frida") || p.contains("gadget") || p.contains("gum-js") || p.contains("linjector")
        }
        out += signal(
            id = "frida_in_memory",
            title = "Frida-библиотеки внутри процесса",
            triggered = mapsHits.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 100,
            why = "Агент Frida уже внутри нашего адресного пространства: любой метод может быть перехвачен прямо сейчас.",
            method = "procfs: /proc/self/maps",
            evidence = mapsHits.take(8).map { ev("region", it.path) },
        )

        val nativeHits = NativeBridge.mapsScan(listOf("frida", "gadget", "gum-js", "linjector"))
        out += signal(
            id = "frida_native_view",
            title = "Нативный скан памяти видит Frida",
            triggered = nativeHits.isNotEmpty() && mapsHits.isEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "Нативное чтение maps нашло агента, а Java-чтение — нет. Значит, чтение процфс из Java уже перехвачено.",
            method = "jni: raw openat(/proc/self/maps)",
            evidence = nativeHits.take(6).map { ev("line", it.takeLast(90)) },
        )

        val ports = ctx.tcpSockets.lineSequence().filter { line ->
            Signatures.FRIDA_PORTS_HEX.any { line.contains(":" + it, ignoreCase = true) }
        }.take(5).toList()
        out += signal(
            id = "frida_ports",
            title = "Открыт стандартный порт Frida (27042/27043)",
            triggered = ports.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "frida-server по умолчанию слушает 27042. Порт виден в /proc/net/tcp без всяких разрешений.",
            method = "procfs: /proc/net/tcp",
            evidence = ports.map { ev("socket", it.trim().take(90)) },
        )

        val threads = runCatching {
            File("/proc/self/task").listFiles()?.mapNotNull { t ->
                runCatching { File(t, "comm").readText().trim() }.getOrNull()
            }.orEmpty()
        }.getOrDefault(emptyList())
        val badThreads = threads.filter { name ->
            name.startsWith("gmain") || name.startsWith("gdbus") || name.startsWith("gum-js") ||
                name.contains("frida") || name.startsWith("pool-frida")
        }
        out += signal(
            id = "frida_threads",
            title = "Потоки с именами Frida/GLib",
            triggered = badThreads.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 92,
            why = "gmain, gdbus и gum-js-loop — служебные потоки frida-gum. В обычном Android-приложении их не бывает.",
            method = "procfs: /proc/self/task/*/comm",
            evidence = badThreads.take(10).map { ev("thread", it) },
        )

        return out
    }
}
