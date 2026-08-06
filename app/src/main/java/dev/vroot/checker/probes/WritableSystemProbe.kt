package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

class WritableSystemProbe : BaseProbe() {
    override val id = "root.writable"
    override val displayName = "Запись в системные каталоги"
    override val category = Category.MOUNTS

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val writable = Signatures.WRITABLE_SYSTEM_DIRS.filter { Sys.canWrite(it) }
        val creatable = Signatures.WRITABLE_SYSTEM_DIRS.filter { Sys.canCreateFileIn(it) }

        return listOf(
            signal(
                id = "canwrite",
                title = "Системные каталоги помечены как записываемые",
                triggered = writable.isNotEmpty(),
                severity = Severity.MEDIUM,
                confidence = 70,
                why = "Для обычного app-uid все эти каталоги должны быть только для чтения.",
                method = "java.io.File.canWrite",
                evidence = writable.map { ev(it, "canWrite=true") },
            ),
            signal(
                id = "can_create",
                title = "Удалось реально создать файл в системном каталоге",
                triggered = creatable.isNotEmpty(),
                severity = Severity.CRITICAL,
                confidence = 100,
                why = "Не просто флаг прав, а фактически созданный и удалённый файл. Без root такое невозможно.",
                method = "createNewFile + delete",
                evidence = creatable.map { ev(it, "created=true") },
            ),
        )
    }
}
