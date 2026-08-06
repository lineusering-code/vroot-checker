package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge
import dev.vroot.checker.core.util.Sys
import java.io.File

/** Frida: server files, default ports, libraries mapped in, and telltale threads. */
class FridaProbe : BaseProbe() {
    override val id = "hook.frida"
    override val displayName = "Frida and dynamic instrumentation"
    override val category = Category.DYNAMIC_ANALYSIS
    override val timeoutMs = 2500L

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()

        val files = Sys.probeAll(Signatures.FRIDA_PATHS).filter { it.exists }
        out += signal(
            id = "server_files",
            title = "frida-server / gadget files on disk",
            triggered = files.isNotEmpty(),
            severity = Severity.HIGH,
            confidence = 90,
            why = "frida-server is usually dropped into /data/local/tmp. Its mere presence says the device was prepared for reverse engineering.",
            method = "java.io.File + faccessat(JNI)",
            evidence = files.map { ev(it.path, it.describe()) },
        )

        val mapsHits = ctx.maps.filter { r ->
            val p = r.path.lowercase()
            p.contains("frida") || p.contains("gadget") || p.contains("gum-js") || p.contains("linjector")
        }
        out += signal(
            id = "frida_in_memory",
            title = "Frida libraries inside this process",
            triggered = mapsHits.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 100,
            why = "The Frida agent is already inside our address space: any method can be intercepted right now.",
            method = "procfs: /proc/self/maps",
            evidence = mapsHits.take(8).map { ev("region", it.path) },
        )

        val nativeHits = NativeBridge.mapsScan(listOf("frida", "gadget", "gum-js", "linjector"))
        out += signal(
            id = "frida_native_view",
            title = "The native memory scan sees Frida",
            triggered = nativeHits.isNotEmpty() && mapsHits.isEmpty(),
            severity = Severity.CRITICAL,
            confidence = 95,
            why = "A native read of maps found the agent while the Java read did not, which means procfs reads from Java are already being intercepted.",
            method = "jni: raw openat(/proc/self/maps)",
            evidence = nativeHits.take(6).map { ev("line", it.takeLast(90)) },
        )

        val ports = ctx.tcpSockets.lineSequence().filter { line ->
            Signatures.FRIDA_PORTS_HEX.any { line.contains(":" + it, ignoreCase = true) }
        }.take(5).toList()
        out += signal(
            id = "frida_ports",
            title = "A default Frida port is open (27042/27043)",
            triggered = ports.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "frida-server listens on 27042 by default, and the port is visible in /proc/net/tcp without any permission.",
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
            title = "Threads named after Frida/GLib internals",
            triggered = badThreads.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 92,
            why = "gmain, gdbus and gum-js-loop are frida-gum worker threads. An ordinary Android app never has them.",
            method = "procfs: /proc/self/task/*/comm",
            evidence = badThreads.take(10).map { ev("thread", it) },
        )

        return out
    }
}
