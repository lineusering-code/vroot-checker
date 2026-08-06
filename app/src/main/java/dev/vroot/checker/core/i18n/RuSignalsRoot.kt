package dev.vroot.checker.core.i18n

/** Russian text for every signal in the Root bucket. Keys are signal ids. */
internal val RU_ROOT_TITLES: Map<String, String> = mapOf(
    "root.binaries.su_binary" to "Бинарник su на диске",
    "root.binaries.su_channel_mismatch" to "Каналы проверки su расходятся",
    "root.binaries.root_tooling" to "Сопутствующий root-тулинг",
    "root.binaries.which_su" to "Root-бинарники доступны через PATH",
    "root.binaries.su_exec" to "Вызов su выдал uid=0",

    "root.manager.magisk_files" to "Артефакты Magisk в файловой системе",
    "root.manager.kernelsu_apatch" to "Следы KernelSU / APatch",
    "root.manager.modules_installed" to "Установленные root-модули",
    "root.manager.magisk_socket" to "Живой сокет root-демона",
    "root.manager.zygisk_in_process" to "Zygisk / Riru внутри нашего процесса",
    "root.manager.zygisk_native_view" to "Нативный скан maps видит то, чего не видит Java",

    "root.mounts.overlay_on_system" to "overlayfs поверх системных разделов",
    "root.mounts.tmpfs_on_system" to "tmpfs на /sbin или внутри /system",
    "root.mounts.system_rw" to "Системный раздел смонтирован на запись",
    "root.mounts.mount_namespace_mismatch" to "/proc/mounts и /proc/self/mountinfo расходятся",
    "root.mounts.magisk_mount_source" to "Источники монтирования Magisk в mountinfo",

    "root.packages.root_apps" to "Установлены приложения root-менеджеров",
    "root.packages.adb_privileged_helper" to "Установлен ADB-помощник с расширенными правами",
    "root.packages.hidden_packages" to "Пакет виден не всем каналам PackageManager",
    "root.packages.clone_apps" to "Установлены инструменты клонирования приложений",
    "root.packages.emulator_apps" to "Сервисные пакеты эмуляторов",

    "root.props.insecure_build" to "Небезопасная сборка (ro.debuggable / ro.secure)",
    "root.props.test_keys" to "Сборка подписана test-keys",
    "root.props.verified_boot" to "Verified Boot не в состоянии green",
    "root.props.resetprop_mismatch" to "Значения свойств различаются между каналами",
    "root.props.dangerous_props" to "Опасные значения свойств",

    "root.selinux.permissive" to "SELinux в режиме permissive",
    "root.selinux.bad_context" to "Нетипичный SELinux-контекст процесса",
    "root.selinux.enforce_writable" to "Файл enforce доступен на запись",

    "root.writable.canwrite" to "Системные каталоги помечены как записываемые",
    "root.writable.can_create" to "Удалось реально создать файл в системном каталоге",
)

internal val RU_ROOT_WHY: Map<String, String> = mapOf(
    "root.binaries.su_binary" to "Файл su — это точка входа для повышения привилегий. На стоковой прошивке его не существует ни по одному из известных путей.",
    "root.binaries.su_channel_mismatch" to "java.io.File и прямой syscall дают разный ответ по одному и тому же пути. Так выглядит работа скрывалки: патчат Java-уровень и забывают про libc.",
    "root.binaries.root_tooling" to "busybox, daemonsu, supolicy, resetprop и Superuser.apk ставятся вместе с root-менеджером и не встречаются на чистой системе.",
    "root.binaries.which_su" to "Если which находит бинарник, он лежит в PATH процесса — значит его даже не пытаются прятать.",
    "root.binaries.su_exec" to "Мы реально получили root-оболочку. Это не косвенный признак, а факт.",

    "root.manager.magisk_files" to "Каталоги /data/adb/magisk, /data/adb/modules и /sbin/.magisk создаёт только Magisk. DenyList прячет монтирования, но сами каталоги обычно остаются читаемыми.",
    "root.manager.kernelsu_apatch" to "KernelSU и APatch — это root на уровне ядра, который вообще не трогает системный раздел, поэтому классические проверки su его не видят. Их рабочие каталоги проверяются отдельно.",
    "root.manager.modules_installed" to "Чтение списка модулей напрямую показывает, что именно привили системе, включая скрытые модули.",
    "root.manager.magisk_socket" to "Абстрактный unix-сокет демона виден в /proc/net/unix. Значит root не просто установлен, а прямо сейчас работает.",
    "root.manager.zygisk_in_process" to "Библиотеки root-фреймворка отображены в адресное пространство этого приложения — то есть кто-то уже забрался внутрь.",
    "root.manager.zygisk_native_view" to "Чтение /proc/self/maps через сырой syscall нашло записи, которых нет в Java-представлении. Значит Java-API файловой системы фильтруется.",

    "root.mounts.overlay_on_system" to "Оверлей поверх /system или /vendor — это способ Magisk и KernelSU подменять системные файлы, не записывая ничего в сам раздел (systemless-режим).",
    "root.mounts.tmpfs_on_system" to "Magisk разворачивает своё окружение в tmpfs, смонтированной на /sbin или /debug_ramdisk. На стоковом устройстве там tmpfs нет.",
    "root.mounts.system_rw" to "На здоровом устройстве настоящий системный раздел всегда ro; rw означает, что был выполнен root-ремоунт. Раздел /apex исключён: он rw по проекту на любом Android 10+.",
    "root.mounts.mount_namespace_mismatch" to "Два описания одного и того же namespace должны совпадать. Большая разница — след манипуляций с mount namespace (MagiskHide / DenyList).",
    "root.mounts.magisk_mount_source" to "Имена источников вида magisk/worker остаются в mountinfo даже после того, как сами файлы спрятаны.",

    "root.packages.root_apps" to "Magisk Manager, SuperSU, LSPosed и им подобные ставят только на модифицированные устройства.",
    "root.packages.adb_privileged_helper" to "Shizuku и аналоги выдают другим приложениям привилегированные API, но работают поверх ADB и запускаются на полностью стоковых устройствах. Знать об этом полезно, но это не признак root.",
    "root.packages.hidden_packages" to "getInstalledPackages не показывает пакет, а getPackageInfo его находит, или наоборот. Именно так работают модули скрытия списка приложений.",
    "root.packages.clone_apps" to "Parallel Space, VirtualApp, App Cloner и подобные умеют запускать чужое приложение внутри своего процесса и полностью контролировать его окружение.",
    "root.packages.emulator_apps" to "BlueStacks, Nox, LDPlayer, MEmu и облачные телефоны зашивают собственные фирменные пакеты в системный образ.",

    "root.props.insecure_build" to "На розничной прошивке всегда ro.debuggable=0 и ro.secure=1. Иначе это eng/userdebug-сборка или подменённые свойства — adb root доступен.",
    "root.props.test_keys" to "Официальные прошивки подписаны release-keys. test-keys означает кастомную или отладочную сборку.",
    "root.props.verified_boot" to "Оранжевый/жёлтый verified boot или выключенный dm-verity — это разблокированный загрузчик. Без него поставить стойкий root практически невозможно.",
    "root.props.resetprop_mismatch" to "Одно и то же свойство читается по-разному через SystemProperties, нативный API и getprop. Так выглядит маскировка (resetprop / hook на свойства).",
    "root.props.dangerous_props" to "Эти свойства явно разрешают root-доступ или небезопасный adb.",

    "root.selinux.permissive" to "На любом розничном устройстве SELinux всегда enforcing. Permissive снимает практически все ограничения между процессами.",
    "root.selinux.bad_context" to "Обычное приложение всегда работает в домене untrusted_app. Контекст magisk/su/init означает, что нас запустил не штатный zygote.",
    "root.selinux.enforce_writable" to "Возможность писать в enforce означает, что режим SELinux можно переключить на лету.",

    "root.writable.canwrite" to "Для обычного app-uid все эти каталоги должны быть только для чтения.",
    "root.writable.can_create" to "Не просто флаг прав, а фактически созданный и удалённый файл. Без root такое невозможно.",
)
