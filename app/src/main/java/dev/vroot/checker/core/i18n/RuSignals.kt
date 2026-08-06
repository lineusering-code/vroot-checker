package dev.vroot.checker.core.i18n

/**
 * Merged lookup tables consumed by [Tr].
 *
 * The per-bucket maps are merged once when the class is initialised, so the
 * cost is a single allocation at first use rather than a lookup across several
 * maps on every rendered row.
 */
internal val RU_SIGNAL_TITLES: Map<String, String> =
    RU_ROOT_TITLES + RU_VIRT_TITLES + RU_HOOK_TITLES

internal val RU_SIGNAL_WHY: Map<String, String> =
    RU_ROOT_WHY + RU_VIRT_WHY + RU_HOOK_WHY

/** Probe display names, keyed by probe id. */
internal val RU_PROBES: Map<String, String> = mapOf(
    "root.binaries" to "Root-бинарники",
    "root.manager" to "Root-менеджеры",
    "root.mounts" to "Точки монтирования",
    "root.props" to "Системные свойства",
    "root.selinux" to "SELinux",
    "root.packages" to "Установленные пакеты",
    "root.writable" to "Запись в системные каталоги",
    "virt.emulator" to "Признаки эмулятора",
    "virt.build" to "Поля Build и fingerprint",
    "virt.hypervisor" to "Гипервизор и архитектура",
    "virt.hardware" to "Железо и сенсоры",
    "virt.appclone" to "Клоны и контейнеры",
    "hook.frida" to "Frida",
    "hook.xposed" to "Xposed / LSPosed",
    "hook.native" to "Нативные хуки",
    "debug.tracer" to "Трейсеры и отладчики",
    "debug.adb" to "Отладка и ADB",
    "integrity.app" to "Целостность приложения",
)
