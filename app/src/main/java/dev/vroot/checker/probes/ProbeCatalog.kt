package dev.vroot.checker.probes

import dev.vroot.checker.core.Probe

/**
 * The single list of every detector in the engine. The order here is the order
 * the checks appear in the report, grouped by bucket so a reader moves from
 * root evidence to virtualization to hooking to integrity.
 */
object ProbeCatalog {
    fun all(): List<Probe> = listOf(
        // ROOT
        RootBinariesProbe(),
        RootManagerProbe(),
        MountProbe(),
        PropsProbe(),
        SelinuxProbe(),
        RootPackagesProbe(),
        WritableSystemProbe(),
        // VIRTUAL
        EmulatorFilesProbe(),
        BuildFingerprintProbe(),
        HypervisorProbe(),
        HardwareProbe(),
        AppCloneProbe(),
        // HOOK
        FridaProbe(),
        XposedProbe(),
        NativeHookProbe(),
        // INTEGRITY
        DebuggerProbe(),
        AdbSettingsProbe(),
        AppIntegrityProbe(),
    )
}
