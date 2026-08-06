package dev.vroot.checker.probes

import dev.vroot.checker.core.BaseProbe
import dev.vroot.checker.core.ProbeContext
import dev.vroot.checker.core.model.Category
import dev.vroot.checker.core.model.Severity
import dev.vroot.checker.core.model.Signal
import dev.vroot.checker.core.util.Sys

/**
 * Write access to read-only system trees.
 *
 * The permission flag and an actual write attempt are reported as separate
 * signals on purpose: canWrite() lies often enough that it only deserves
 * MEDIUM, while a file that was really created and removed is proof.
 */
class WritableSystemProbe : BaseProbe() {
    override val id = "root.writable"
    override val displayName = "Writable system directories"
    override val category = Category.MOUNTS

    override suspend fun run(ctx: ProbeContext): List<Signal> {
        val writable = Signatures.WRITABLE_SYSTEM_DIRS.filter { Sys.canWrite(it) }
        val creatable = Signatures.WRITABLE_SYSTEM_DIRS.filter { Sys.canCreateFileIn(it) }

        return listOf(
            signal(
                id = "canwrite",
                title = "System directories report themselves as writable",
                triggered = writable.isNotEmpty(),
                severity = Severity.MEDIUM,
                confidence = 70,
                why = "For an ordinary app uid every one of these directories must be read-only.",
                method = "java.io.File.canWrite",
                evidence = writable.map { ev(it, "canWrite=true") },
            ),
            signal(
                id = "can_create",
                title = "A file was actually created in a system directory",
                triggered = creatable.isNotEmpty(),
                severity = Severity.CRITICAL,
                confidence = 100,
                why = "Not a permission flag but a file that was really created and deleted. That is impossible without root.",
                method = "createNewFile + delete",
                evidence = creatable.map { ev(it, "created=true") },
            ),
        )
    }
}
