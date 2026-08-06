package dev.vroot.checker.core.i18n

/** Russian text for every signal in the Virtual bucket. Keys are signal ids. */
internal val RU_VIRT_TITLES: Map<String, String> = mapOf(
    "virt.appclone.datadir_mismatch" to "dataDir не соответствует имени пакета",
    "virt.appclone.weird_uid" to "Нетипичный UID процесса",
    "virt.appclone.foreign_data_maps" to "В память отображён код из чужого каталога данных",
    "virt.appclone.cgroup_shape" to "Нетипичная cgroup процесса",
    "virt.appclone.exe_path" to "Процесс запущен не штатным app_process",

    "virt.build.build_tokens" to "Маркеры эмулятора в Build.*",
    "virt.build.fingerprint_inconsistent" to "Fingerprint не совпадает с брендом",
    "virt.build.fingerprint_mismatch" to "Build.FINGERPRINT отличается от ro.build.fingerprint",

    "virt.emulator.emulator_files" to "Файлы эмулятора на диске",
    "virt.emulator.goldfish_tty" to "Драйвер goldfish в /proc/tty/drivers",
    "virt.emulator.qemu_props" to "QEMU-свойства системы",
    "virt.emulator.kernel_banner" to "Виртуальная платформа в баннере ядра",

    "virt.hardware.sensors" to "Набор сенсоров неправдоподобен",
    "virt.hardware.cameras" to "Камеры отсутствуют",
    "virt.hardware.battery" to "Показания батареи синтетичны",
    "virt.hardware.telephony" to "Телефония выглядит эмулированной",
    "virt.hardware.mac_oui" to "MAC-адрес из диапазона виртуализации",
    "virt.hardware.uptime" to "Подозрительно малый uptime",
    "virt.hardware.thermal_zones" to "Нет термозон",

    "virt.hypervisor.hypervisor_flag" to "Флаг hypervisor в /proc/cpuinfo",
    "virt.hypervisor.x86_device" to "Только x86-набор ABI",
    "virt.hypervisor.hypervisor_nodes" to "Узлы гипервизора в sysfs/dev",
    "virt.hypervisor.cpuinfo_shape" to "В /proc/cpuinfo нет строк Hardware/Serial",
)

internal val RU_VIRT_WHY: Map<String, String> = mapOf(
    "virt.appclone.datadir_mismatch" to "Обычно dataDir — это /data/user/0/<пакет>. Путь, ведущий в каталог другого приложения, означает, что нас запустил контейнер.",
    "virt.appclone.weird_uid" to "Обычные приложения получают UID в диапазоне 10000..19999 для первого пользователя. Значительно больший UID — это рабочий профиль или клон, меньший — системный контекст.",
    "virt.appclone.foreign_data_maps" to "Исполняемый код, загруженный из каталога данных другого пакета, — это принцип работы контейнеров вроде VirtualApp. Общие ресурсы вроде шрифтов эмодзи из Play Services исключены: их отображает каждое приложение на устройстве.",
    "virt.appclone.cgroup_shape" to "Android помещает приложения в cgroup, в пути которой есть uid_ или apps. Отклонения встречаются в контейнерах и облачных телефонах.",
    "virt.appclone.exe_path" to "Каждое Android-приложение стартует через app_process как форк zygote. Другой исполняемый файл означает подменённый runtime.",

    "virt.build.build_tokens" to "В полях Build у эмуляторов встречаются характерные слова (generic, sdk_gphone, vbox86, ranchu). Чем больше полей совпало, тем меньше шанс совпадения. Плейсхолдеры вроде BOOTLOADER=unknown игнорируются: розничные телефоны тоже их поставляют.",
    "virt.build.fingerprint_inconsistent" to "На стоковой прошивке fingerprint всегда начинается с имени бренда. Расхождение означает подмену полей Build — модулем либо эмулятором, притворяющимся телефоном.",
    "virt.build.fingerprint_mismatch" to "Java-поле и системное свойство берутся из одного источника. Они расходятся только тогда, когда один из слоёв активно переписывают.",

    "virt.emulator.emulator_files" to "qemu_pipe, goldfish/ranchu init-скрипты, vbox-устройства и фирменные бинарники эмуляторов на реальном телефоне не существуют.",
    "virt.emulator.goldfish_tty" to "goldfish — это виртуальная платформа Android Emulator. Её tty-драйвер не встречается на физическом железе.",
    "virt.emulator.qemu_props" to "Свойства ro.kernel.qemu и qemu.* выставляет сам эмулятор при загрузке системы.",
    "virt.emulator.kernel_banner" to "Строка версии ядра содержит имя виртуальной платформы, а не вендора SoC.",

    "virt.hardware.sensors" to "У реального телефона десятки сенсоров от реальных вендоров. Эмуляторы отдают короткий список с вендором AOSP/Goldfish.",
    "virt.hardware.cameras" to "Телефонов без единой камеры практически не бывает, а у части виртуалок и облачных телефонов камер нет вообще.",
    "virt.hardware.battery" to "Эмуляторы отдают фиксированные значения: вечные 100%, подключённое питание и температуру 25.0 °C или 0.",
    "virt.hardware.telephony" to "Оператор с именем Android — зашитый дефолт эмулятора AOSP.",
    "virt.hardware.mac_oui" to "Префиксы OUI 08:00:27 (VirtualBox), 00:0c:29 (VMware), 52:54:00 (QEMU/KVM) выдают виртуальный сетевой адаптер.",
    "virt.hardware.uptime" to "Свежезагруженная система типична для одноразовых виртуалок и ферм эмуляторов, где образ поднимается под задачу.",
    "virt.hardware.thermal_zones" to "У реального SoC всегда есть термодатчики в /sys/class/thermal. Пустой каталог — признак виртуального железа.",

    "virt.hypervisor.hypervisor_flag" to "Процессор сам сообщает, что код исполняется под гипервизором. Это виртуальная машина, а не телефон.",
    "virt.hypervisor.x86_device" to "Подавляющее большинство реальных Android-устройств — это ARM. Чистый x86/x86_64 почти всегда означает эмулятор, Android-x86 или WSA.",
    "virt.hypervisor.hypervisor_nodes" to "/dev/kvm, vmbus или заполненный /sys/hypervisor внутри гостевой системы означают виртуализацию. Пустой каталог /sys/hypervisor игнорируется: стоковые ARM-ядра создают его пустым и нечитаемым.",
    "virt.hypervisor.cpuinfo_shape" to "Старые ARM-устройства печатали строки Hardware/Serial, а эмуляторы часто нет. Современные ядра убрали эти строки и на реальном железе, поэтому это контекст для лога, а не улика.",
)
