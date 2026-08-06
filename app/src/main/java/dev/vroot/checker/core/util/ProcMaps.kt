package dev.vroot.checker.core.util

data class MapRegion(
    val start: Long,
    val end: Long,
    val perms: String,
    val path: String,
) {
    val executable: Boolean get() = perms.length > 2 && perms[2] == 'x'
    val anonymous: Boolean get() = path.isBlank()
    val size: Long get() = end - start
}

object ProcMaps {

    private val LINE = Regex("^([0-9a-f]+)-([0-9a-f]+)\\s+(\\S{4})\\s+\\S+\\s+\\S+\\s+\\S+\\s*(.*)$")

    fun readSelf(): List<MapRegion> = parse(Sys.readText("/proc/self/maps"))

    fun parse(text: String): List<MapRegion> = text.lineSequence().mapNotNull { line ->
        val m = LINE.find(line.trim()) ?: return@mapNotNull null
        runCatching {
            MapRegion(
                start = m.groupValues[1].toLong(16),
                end = m.groupValues[2].toLong(16),
                perms = m.groupValues[3],
                path = m.groupValues[4].trim(),
            )
        }.getOrNull()
    }.toList()

    /** Ищет подстроки в путях регионов (регистронезависимо). */
    fun findPaths(regions: List<MapRegion>, needles: Collection<String>): List<Pair<String, String>> {
        val hits = ArrayList<Pair<String, String>>()
        regions.forEach { r ->
            val lower = r.path.lowercase()
            needles.forEach { n ->
                if (lower.contains(n.lowercase())) hits.add(n to r.path)
            }
        }
        return hits.distinctBy { it.second }
    }

    /**
     * Исполняемые анонимные регионы приличного размера — классика
     * инжекта кода (gadget, шеллкод, JIT-стаб чужого фреймворка).
     */
    fun suspiciousAnonExec(regions: List<MapRegion>, minSize: Long = 64 * 1024): List<MapRegion> =
        regions.filter { it.executable && it.anonymous && it.size >= minSize }
}
