package dev.vroot.checker.core.i18n

/** Russian text for the Hooking and Integrity buckets. Keys are signal ids. */
internal val RU_HOOK_TITLES: Map<String, String> = mapOf(
    "hook.frida.server_files" to "Файлы frida-server / gadget на диске",
    "hook.frida.frida_in_memory" to "Frida-библиотеки внутри процесса",
    "hook.frida.frida_native_view" to "Нативный скан памяти видит Frida",
    "hook.frida.frida_ports" to "Открыт стандартный порт Frida (27042/27043)",
    "hook.frida.frida_threads" to "Потоки с именами Frida/GLib",

    "hook.native.inline_hooks" to "Прологи функций libc пропатчены",
    "hook.native.anon_exec" to "Исполняемые анонимные области памяти",
    "hook.native.deleted_mappings" to "В память отображены удалённые файлы кода",
    "hook.native.foreign_libs" to "Библиотеки .so загружены из нетипичных мест",

    "hook.xposed.classes_loadable" to "Классы хук-фреймворка резолвятся в нашем загрузчике",
    "hook.xposed.framework_files" to "Файлы Xposed / LSPosed / Riru на диске",
    "hook.xposed.stack_injection" to "Кадры хук-фреймворка в стеке вызовов",
    "hook.xposed.hook_libs_mapped" to "Библиотеки перехвата отображены в процесс",
    "hook.xposed.xposed_prop" to "Установлено свойство ro.xposed.version",

    "debug.adb.adb_enabled" to "Отладка по USB включена",
    "debug.adb.dev_settings" to "Меню разработчика активно",
    "debug.adb.mock_location" to "Разрешены фиктивные локации",
    "debug.adb.adb_secure_prop" to "Отключена авторизация ADB",
    "debug.adb.adb_over_tcp" to "ADB слушает по сети",

    "debug.tracer.tracer_pid" to "К процессу подключён трейсер",
    "debug.tracer.jdwp" to "Подключён Java-отладчик",
    "debug.tracer.ptrace_self" to "Слот ptrace уже занят",
    "debug.tracer.seccomp_off" to "Фильтр seccomp отключён",

    "integrity.app.debuggable_flag" to "Релизная сборка помечена флагом debuggable",
    "integrity.app.signature" to "Подпись APK не совпадает с ожидаемой",
    "integrity.app.installer" to "Установлено не из доверенного магазина",
    "integrity.app.foreign_native_libs" to "Лишние .so в каталоге библиотек приложения",
    "integrity.app.apk_location" to "APK лежит вне /data/app",
)

internal val RU_HOOK_WHY: Map<String, String> = mapOf(
    "hook.frida.server_files" to "frida-server обычно кладут в /data/local/tmp. Сам факт наличия говорит, что устройство готовили к реверсу.",
    "hook.frida.frida_in_memory" to "Агент Frida уже внутри нашего адресного пространства: любой метод может быть перехвачен прямо сейчас.",
    "hook.frida.frida_native_view" to "Нативное чтение maps нашло агента, а Java-чтение — нет. Значит, чтение процфс из Java уже перехвачено.",
    "hook.frida.frida_ports" to "frida-server по умолчанию слушает 27042. Порт виден в /proc/net/tcp без всяких разрешений.",
    "hook.frida.frida_threads" to "gmain, gdbus и gum-js-loop — служебные потоки frida-gum. В обычном Android-приложении их не бывает.",

    "hook.native.inline_hooks" to "Первые инструкции функции заменены безусловным переходом — это форма трамплина, который ставят Dobby, frida-gum или Substrate. Файловым вызовам больше нельзя доверять.",
    "hook.native.anon_exec" to "Большие rx-области без файла на диске — классический признак внедрённого кода, хотя часть таких областей законно создаёт JIT среды ART, отсюда умеренный вес.",
    "hook.native.deleted_mappings" to "Загрузить .so и сразу удалить файл — классический способ спрятать внедрённую библиотеку от проверок по пути. JIT-кэши и области ashmem исключены: их показывает удалёнными любой нормальный процесс ART.",
    "hook.native.foreign_libs" to "Нативные библиотеки должны приходить из системного раздела только для чтения или из каталога самого приложения. Всё остальное туда положил кто-то посторонний.",

    "hook.xposed.classes_loadable" to "XposedBridge и его форки внедряются в каждый процесс, который они инструментируют. Если класс резолвится, фреймворк активен прямо здесь.",
    "hook.xposed.framework_files" to "XposedBridge.jar, /data/adb/lspd и каталоги riru поставляются только вместе с фреймворком перехвата.",
    "hook.xposed.stack_injection" to "Когда метод активно хукнут, между нашими вызовами появляются кадры самого фреймворка. Кадры этого приложения исключены, иначе проба находила бы саму себя.",
    "hook.xposed.hook_libs_mapped" to "libsubstrate, libdobby, lsplant, sandhook и подобные существуют ради одного: переписывать чужой код во время выполнения.",
    "hook.xposed.xposed_prop" to "Это свойство выставляет сам установщик Xposed.",

    "debug.adb.adb_enabled" to "С включённым ADB любой, кто получит физический доступ к устройству, может залить frida-server или вытащить данные приложений. Это настройка пользователя, а не признак вмешательства.",
    "debug.adb.dev_settings" to "Само по себе не угроза, но это предварительное условие для ADB, мок-локаций и отладки приложений.",
    "debug.adb.mock_location" to "Подмена GPS часто идёт в комплекте с клонами и эмуляторами для обхода геопроверок.",
    "debug.adb.adb_secure_prop" to "ro.adb.secure=0 или ro.secure=0 означают eng/userdebug-сборку: adb подключается без подтверждения и часто сразу как root.",
    "debug.adb.adb_over_tcp" to "Активный TCP-порт ADB открывает устройство для удалённого управления из локальной сети.",

    "debug.tracer.tracer_pid" to "TracerPid в /proc/self/status не равен нулю: кто-то выполнил PTRACE_ATTACH и читает или переписывает нашу память. Именно так работают frida-server и gdb.",
    "debug.tracer.jdwp" to "Сессия JDWP позволяет ставить точки останова и переписывать переменные на лету.",
    "debug.tracer.ptrace_self" to "Процесс может трассироваться только одним трейсером одновременно. Наша контрольная попытка подключиться отклонена, значит слот занят кем-то другим.",
    "debug.tracer.seccomp_off" to "Штатный zygote ставит каждому приложению фильтр seccomp (режим 2). Режим 0 встречается на модифицированных сборках и в контейнерах.",

    "integrity.app.debuggable_flag" to "FLAG_DEBUGGABLE позволяет любому подключить отладчик и использовать run-as без root. У релизного APK его быть не должно. Для этой отладочной сборки он ожидаем.",
    "integrity.app.signature" to "Если отпечаток сертификата отличается от ожидаемого, APK распаковали, изменили и подписали заново.",
    "integrity.app.installer" to "Пустой установщик означает adb или файловый менеджер. Для диагностической утилиты это нормально, отсюда минимальный вес.",
    "integrity.app.foreign_native_libs" to "Наш APK поставляет ровно одну нативную библиотеку. Всё, что лежит рядом, — след переупаковки или внедрения gadget.",
    "integrity.app.apk_location" to "Нормально установленные приложения лежат в /data/app. Другой путь типичен для контейнеров и предустановленных подмен.",
)
