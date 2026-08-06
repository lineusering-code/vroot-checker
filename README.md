# Vroot Checker

Жёсткий детектор root / виртуализации / хуков для Android. 18 независимых пробов, сотни сигналов, полный читаемый лог с объяснением «что / почему / как проверено» и экспорт отчёта в JSON и Markdown.

UI — Material 3 (Jetpack Compose), тёмная/светлая тема, dynamic color, единый набор vector-иконок в стиле Android.

---

## Что проверяется

Сигналы сгруппированы в 4 корзины: **Root**, **Virtual**, **Hooking**, **Integrity**.

### Root (7 пробов)
| ID | Что делает |
|---|---|
| `root.binaries` | Поиск `su`, `busybox`, `magisk`, `ksud` и других бинарников по десяткам путей (Java + native `access()`, сравнение результатов — ловит сокрытие через хуки) |
| `root.manager` | Артефакты Magisk / KernelSU / APatch: файлы, сокеты, `magisk` в `/proc/net/unix`, следы Zygisk |
| `root.mounts` | Анализ `/proc/self/mounts` и `mountinfo`: rw на `/system`, `overlayfs`, `tmpfs` в системных точках, скрытые bind-mount, расхождение mounts и mountinfo |
| `root.props` | `ro.debuggable`, `ro.secure`, `ro.build.tags=test-keys`, `ro.build.type=userdebug/eng`, расхождение Java-API и native `__system_property_get` |
| `root.selinux` | Режим SELinux (`enforce`), доступность `/sys/fs/selinux`, permissive-контекст процесса |
| `root.packages` | Установленные root-приложения и скрыватели (Magisk Manager, Shamiko, LSPosed, HideMyApplist и т.д.) |
| `root.writable` | Попытка записи в `/system`, `/vendor`, `/data/local`, `/etc` и др. |

### Virtual (5 пробов)
| ID | Что делает |
|---|---|
| `virt.emulator` | Файлы и пакеты QEMU / Genymotion / BlueStacks / Nox / LDPlayer, `qemu_pipe`, `goldfish` |
| `virt.build` | Build-поля и токены (`generic`, `sdk`, `vbox`, `ranchu`), несогласованный fingerprint |
| `virt.hypervisor` | Флаги `/proc/cpuinfo`, гипервизор-сигнатуры, нетипичные ABI для железа |
| `virt.hardware` | Камеры, датчики, батарея, телефония, `tty`-драйверы, число ядер и объём RAM |
| `virt.appclone` | Запуск в клоне / work-профиле / VirtualApp-контейнере: путь к data, uid, посторонние процессы, счётчик fd |

### Hooking (3 проба)
| ID | Что делает |
|---|---|
| `hook.frida` | Файлы frida-server, строки в памяти, native-обзор маппингов, порты 27042/27043 в `/proc/net/tcp`, подозрительные потоки (`gmain`, `gum-js-loop`) |
| `hook.xposed` | Загружаемые Xposed/LSPosed классы, файлы фреймворка, следы в stack trace, хук-библиотеки в маппингах, `ro.xposed` свойства |
| `hook.native` | Inline-хуки в прологах функций libc, анонимные rwx-регионы, `(deleted)` маппинги, чужие `.so` в адресном пространстве |

### Integrity (3 проба)
| ID | Что делает |
|---|---|
| `debug.tracer` | `TracerPid`, JDWP, `ptrace(PTRACE_TRACEME)` self-test, режим seccomp |
| `debug.adb` | ADB включён, режим разработчика, mock location, `ro.adb.secure`, ADB по TCP |
| `integrity.app` | Флаг `debuggable`, SHA-256 подписи, installer package, посторонние native-библиотеки, расположение APK |

---

## Как считается вердикт

Каждый сигнал имеет вес (`INFO 0`, `LOW 8`, `MEDIUM 18`, `HIGH 32`, `CRITICAL 55`) и уверенность 0–100 %.

```
score = Σ (вес × уверенность / 100)
normalized = 100 × (1 − e^(−score / 70))
```

| Нормализованный балл | Вердикт |
|---|---|
| < 15 | **Clean** — признаков не найдено |
| 15–35 | **Suspicious** — есть отдельные аномалии |
| 35–65 | **Compromised** — среда изменена |
| > 65 | **Hostile** — активное вмешательство |

Любой `CRITICAL` сигнал с уверенностью ≥ 90 % принудительно даёт вердикт **Hostile** (в отчёте видно поле `forcedBy`).

---

## Лог и объяснения

Лог пишется по ходу сканирования с уровнями `TRC / INF / HIT / OK / WRN / ERR`, таймингом от старта и раскрываемыми деталями:

```
[HIT] 00.412s root.binaries  su_path /system/xbin/su
      Почему: бинарник su доступен — на стоковой прошивке его нет
      Метод: File.exists() + native access(F_OK)
      Вес: CRITICAL · уверенность 100% · вклад 55
      Улики:
        • path = /system/xbin/su
        • java = true
        • native = true
```

На вкладке **Лог** есть поиск по тексту и фильтры по уровням.

---

## Экспорт

Кнопка экспорта открывает нижнюю панель с отдельными действиями для каждого формата:

| Формат | Буфер | Поделиться | Сохранить |
|---|---|---|---|
| JSON (schema v1) | ✓ | `.json` через FileProvider | ✓ в Downloads |
| Markdown | ✓ | `.md` через FileProvider | ✓ в Downloads |
| Только лог | ✓ | — | — |

Имя файла: `vroot-<model>-<yyyyMMdd-HHmmss>.<ext>`.

В отчёт входят: вердикт и баллы по корзинам, отпечаток устройства, все пробы с таймингами, каждый сработавший сигнал с уликами и полный лог.

---

## Архитектура

```
app/src/main/
  cpp/                    JNI: access(), чтение /proc, свойства, ptrace, скан маппингов, inline-hook check
  java/dev/vroot/checker/
    core/                 движок, модели, лог, утилиты (Sys, Props, Shell, ProcMaps, Pkg, NativeBridge)
    probes/               18 пробов + сигнатуры + каталог
    report/               JSON, Markdown, Exporter (буфер/share/Downloads)
    ui/                   Compose UI: Dashboard, Log, About
  res/drawable/           единый набор vector-иконок
```

Каждый проб изолирован: свой таймаут (по умолчанию 1800 мс), ошибка или таймаут одного проба не ломает скан — это видно в отчёте.

---

## Сборка

Требования: JDK 17, Android SDK 35, NDK + CMake 3.22.1, Gradle 8.11.1 (AGP 8.9.1, Kotlin 2.1.20), minSdk 26.

```bash
git clone https://github.com/lineusering-code/vroot-checker.git
cd vroot-checker
gradle wrapper --gradle-version 8.11.1   # если нет gradlew в репо
./gradlew assembleDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`.

---

## Ограничения

Детект работает в user-space, поэтому против агрессивных скрывателей (Zygisk + Shamiko + денай-лист) часть проверок может молчать. Именно поэтому сделаны перекрёстные проверки (Java против native, mounts против mountinfo, свойства против `__system_property_get`) — расхождение само по себе является сигналом.

Инструмент — для диагностики своих устройств и исследований безопасности.

---

## Автор

**lineusering-code** — https://github.com/lineusering-code

Репозиторий: https://github.com/lineusering-code/vroot-checker  
Баги и идеи: https://github.com/lineusering-code/vroot-checker/issues

Лицензия: MIT.
