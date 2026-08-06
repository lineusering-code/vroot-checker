package dev.vroot.checker.probes

import dev.vroot.checker.core.Probe

/** Единый список всех детекторов движка. Порядок = порядок отображения в отчёте. */
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
