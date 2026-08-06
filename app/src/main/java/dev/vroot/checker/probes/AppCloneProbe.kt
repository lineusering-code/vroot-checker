package dev.vroot.checker.probes

import android.os.Process
import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.NativeBridge

/**
 * Запуск внутри контейнера (VirtualApp, Parallel Space, Dual Apps, Island).
 * Ключевая идея: в таком режиме процесс физически принадлежит чужому пакету.
 */
class AppCloneProbe : BaseProbe() {
    override val id = "virt.appclone"
    override val displayName = "Клоны и контейнеры"
    override val category = Category.APP_CLONE

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val out = ArrayList<Signal>()
        val pkg = ctx.selfPackage

        val dataDir = runCatching { ctx.app.applicationInfo.dataDir.orEmpty() }.getOrDefault("")
        out += signal(
            id = "datadir_mismatch",
            title = "dataDir не совпадает с именем пакета",
            triggered = dataDir.isNotEmpty() && !dataDir.endsWith("/" + pkg),
            severity = Severity.HIGH,
            confidence = 85,
            why = "Обычно dataDir — это /data/user/0/<package>. Если путь ведёт в каталог другого приложения, значит нас запустил контейнер.",
            method = "ApplicationInfo.dataDir",
            evidence = listOf(ev("dataDir", dataDir), ev("package", pkg)),
        )

        val uid = Process.myUid()
        out += signal(
            id = "weird_uid",
            title = "Нетипичный UID процесса",
            triggered = uid > 999_999 || uid < 10_000,
            severity = Severity.MEDIUM,
            confidence = 70,
            why = "Обычные приложения получают UID в диапазоне 10000..19999 для первого пользователя. Слишком большой UID — рабочий профиль/клон, слишком маленький — системный контекст.",
            method = "Process.myUid + getuid(JNI)",
            evidence = listOf(ev("uid_java", uid), ev("uid_native", NativeBridge.uid())),
        )

        val foreignPkgRegions = ctx.maps.filter { r ->
            r.path.startsWith("/data/data/") || r.path.startsWith("/data/user/")
        }.filter { !it.path.contains(pkg) }
        out += signal(
            id = "foreign_data_maps",
            title = "В памяти замаплены файлы чужого приложения",
            triggered = foreignPkgRegions.isNotEmpty(),
            severity = Severity.CRITICAL,
            confidence = 90,
            why = "В адресное пространство загружен код из data-каталога другого пакета — так работают VirtualApp-подобные контейнеры.",
            method = "procfs: /proc/self/maps",
            evidence = foreignPkgRegions.take(8).map { ev("region", it.path) },
        )

        val cgroup = ctx.selfCgroup
        val cgroupOdd = cgroup.isNotEmpty() && !cgroup.contains("uid_") && !cgroup.contains("apps")
        out += signal(
            id = "cgroup_shape",
            title = "Нетипичный cgroup процесса",
            triggered = cgroupOdd,
            severity = Severity.LOW,
            confidence = 55,
            why = "Android помещает приложения в cgroup с uid_/apps в пути. Отклонение бывает в контейнерах и облачных телефонах.",
            method = "procfs: /proc/self/cgroup",
            evidence = listOf(ev("cgroup", cgroup.lineSequence().firstOrNull().orEmpty().take(120))),
        )

        val exe = NativeBridge.readlink("/proc/self/exe").orEmpty()
        out += signal(
            id = "exe_path",
            title = "Процесс запущен не штатным app_process",
            triggered = exe.isNotEmpty() && !exe.contains("app_process"),
            severity = Severity.HIGH,
            confidence = 80,
            why = "Любое Android-приложение запускается через app_process (форк zygote). Другой исполняемый файл означает подменённый рантайм.",
            method = "jni: readlink(/proc/self/exe)",
            evidence = listOf(ev("exe", exe)),
        )

        return out
    }
}
