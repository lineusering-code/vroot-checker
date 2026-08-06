# 🛡️ Vroot Checker

**Жёсткая диагностика окружения Android: Root · Virtual · Hook · Integrity.**

Vroot Checker — это движок глубокой диагностики среды выполнения. Идея как в «diagnostics» у RootVm, только сильно злее: не один-два чека `/system/bin/su`, а **13 категорий, 20 проб, 120+ независимых сигналов**, каждый со своим весом, уверенностью (confidence) и доказательствами (evidence), плюс нативный слой на прямых syscall'ах, который тяжело обмануть хуками в Java.

---

## 🔥 Что умеет

### 1. Root
| Проба | Что ловит |
|---|---|
| `root.binaries` | `su`, `busybox`, `magisk`, `resetprop`, `supolicy`, `daemonsu` по 30+ путям — через `File`, через `PATH`, через нативный `faccessat`, через `stat()` |
| `root.magisk` | Magisk / Magisk Delta, Zygisk, `/data/adb/magisk`, `magisk.db`, modules, `/proc/net/unix` сокеты Magisk, MagiskHide/DenyList артефакты |
| `root.ksu` | KernelSU (`ksud`, `/data/adb/ksu`, KSU prctl-канал), APatch, Dynamic KernelSU |
| `root.mounts` | overlay/tmpfs на системных точках, `/sbin` как tmpfs, расхождение `/proc/mounts` vs `/proc/self/mountinfo` (классика Magisk mount namespace) |
| `root.props` | `ro.debuggable=1`, `ro.secure=0`, `ro.build.tags=test-keys`, `ro.build.type=userdebug/eng`, `ro.boot.verifiedbootstate != green`, `ro.boot.flash.locked=0`, `ro.boot.veritymode=disabled`, подменённые resetprop-значения |
| `root.selinux` | Permissive, контексты `u:r:magisk:s0`, `u:r:su:s0`, доступность `/sys/fs/selinux/enforce` на запись |
| `root.packages` | 40+ пакетов: Magisk Manager (в т.ч. рандомизированные stub'ы), SuperSU, KingRoot, Kingo, LSPosed, Shizuku, RootCloak, Hide My Root и т.д. |
| `root.writable` | Запись в `/system`, `/vendor`, `/product`, `/data/local`, `remount` возможности |

### 2. Virtual
| Проба | Что ловит |
|---|---|
| `virt.emulator` | goldfish / ranchu / QEMU: `/dev/qemu_pipe`, `/dev/socket/qemud`, `ueventd.goldfish.rc`, `libc_malloc_debug_qemu.so`, `/proc/tty/drivers` |
| `virt.build` | `Build.FINGERPRINT/MODEL/PRODUCT/HARDWARE/BOARD/BRAND/DEVICE` — 60+ паттернов (generic, sdk_gphone, vbox86, emu64, cancro, unknown …), кросс-проверка на противоречия |
| `virt.hypervisor` | Флаг `hypervisor` в `/proc/cpuinfo`, MSR-подобные аномалии, x86-ABI на «телефоне», `/sys/hypervisor`, KVM-артефакты |
| `virt.vendors` | BlueStacks, Nox, LDPlayer, MEmu, Genymotion, MuMu, VirtualBox (`vboxguest`, `vboxsf`), Android-x86, WSA, Redfinger / VMOS / облачные телефоны |
| `virt.hardware` | Сенсоры (кол-во/имена), камеры, батарея (вечные 100% / AC), Bluetooth, `/sys/class/thermal`, MAC `02:00:00:00:00:00`, оператор «Android», IMEI `000000…` |
| `virt.timing` | Uptime, дрейф `SystemClock.elapsedRealtime` vs монотоника, аномалии таймингов инструкций (софтверная эмуляция медленнее) |
| `virt.appclone` | VirtualApp / Parallel Space / Dual Apps / Island / DroidPlugin: UID > 999999, чужой пакет в `/proc/self/maps`, несовпадение `dataDir` и `packageName`, несколько копий процесса, `/proc/self/cgroup` |

### 3. Hooking / Debug
| Проба | Что ловит |
|---|---|
| `hook.frida` | Frida-server процессы, дефолтные порты 27042/27043, `frida-gadget`/`gum-js-loop` в `/proc/self/maps` и в списке потоков, D-Bus AUTH-хендшейк на localhost |
| `hook.xposed` | Xposed / EdXposed / LSPosed / Riru / Dobby / Substrate: stacktrace-инъекции, classloader, `XposedBridge`, `/data/adb/lspd`, artefacts в maps |
| `hook.native` | Инлайн-хуки: проверка пролога `open/read/dlopen` в `libc` на `br/b/ldr` патчи, PLT/GOT аномалии, чужие RX-регионы без файла |
| `debug.tracer` | `TracerPid != 0`, `ptrace(PTRACE_TRACEME)` self-attach тест, seccomp-режим, `/proc/self/status` |
| `debug.adb` | ADB enabled, Developer options, USB-debugging, mock location, `adb_wifi_enabled`, `ro.adb.secure=0` |

### 4. Integrity
- Подпись APK (SHA-256 сертификата) vs эталон;
- `FLAG_DEBUGGABLE`, отладчик подключён/ждёт;
- installer package (Play / sideload / unknown);
- переупаковка: CRC dex/native-либ, чужие `.so` в `nativeLibraryDir`;
- `Build.getSerial`/props подменены;
- работа под другим UID / shared user id.

---

## 🧮 Модель скоринга

Каждый сигнал:

```
score = severity.weight × confidence / 100
severity: INFO(0) LOW(8) MEDIUM(18) HIGH(32) CRITICAL(55)
```

Скоры складываются в 4 бакета — **root / virtual / hook / integrity** — и нормируются 0..100.

Вердикт:

| Total | Verdict |
|---|---|
| 0–14 | `CLEAN` |
| 15–34 | `SUSPICIOUS` |
| 35–64 | `COMPROMISED` |
| 65–100 | `HOSTILE` |

Вердикт также форсится до `HOSTILE`, если сработал любой `CRITICAL` сигнал с confidence ≥ 90 (например, живой Magisk-сокет или активный Frida).

---

## 🏗 Архитектура

```
app/src/main/java/dev/vroot/checker/
├── core/
│   ├── model/Models.kt        # Signal, Severity, Category, Verdict, отчёты
│   ├── Probe.kt               # интерфейс пробы + ProbeContext
│   ├── ProbeContext.kt        # общий кэш: props, mounts, maps, cpuinfo, packages
│   ├── DetectorEngine.kt      # параллельный запуск, таймауты, агрегация, скоринг
│   └── util/                  # Sys, Props, Shell, Maps, Pkg, NativeBridge
├── probes/                    # 20 проб (root.*, virt.*, hook.*, debug.*, integrity.*)
├── report/JsonReport.kt       # экспорт отчёта в JSON
└── ui/                        # Compose UI: вердикт, бары по категориям, дерево сигналов
app/src/main/cpp/vroot_native.c # JNI: faccessat/stat/openat напрямую, maps, TracerPid, хук-чек
```

Принципы:

1. **Многоканальность.** Один и тот же факт проверяется 2–4 разными способами (Java API → shell → нативный syscall). Если каналы расходятся — это само по себе сигнал (`*.mismatch`), потому что расхождение = кто-то врёт.
2. **Никаких падений.** Каждая проба изолирована: исключение превращается в `failed`-пробу, а не в краш.
3. **Параллельно и с таймаутом.** Все пробы едут в `Dispatchers.IO` через `coroutineScope`, каждая с персональным таймаутом (по умолчанию 1500 мс).
4. **Кэш общий.** `/proc/self/maps`, `/proc/mounts`, `cpuinfo`, список пакетов читаются один раз на скан.
5. **Evidence-first.** Каждый сработавший сигнал обязан приложить, что именно нашёл.

---

## 🚀 Использование как библиотеки

```kotlin
val report = DetectorEngine(context).scan()

when (report.verdict) {
    Verdict.CLEAN       -> allow()
    Verdict.SUSPICIOUS  -> stepUpAuth()
    Verdict.COMPROMISED,
    Verdict.HOSTILE     -> block(report.topSignals(5))
}

Log.d("vroot", JsonReport.toJson(report))
```

Точечно:

```kotlin
val engine = DetectorEngine(context, config = EngineConfig(
    probeTimeoutMs = 2500,
    enabledCategories = setOf(Category.ROOT, Category.HOOKING),
    allowShell = false           // полностью без exec(), только File + JNI
))
```

---

## 🔨 Сборка

```bash
git clone https://github.com/lineusering-code/vroot-checker
cd vroot-checker
gradle wrapper --gradle-version 8.9   # wrapper-jar не хранится в репо
./gradlew assembleDebug
```

Требования: JDK 17, Android SDK 35, NDK 26+, CMake 3.22+.

---

## ⚠️ Дисклеймер

Проект предназначен для **защиты собственных приложений** (антифрод, банкинг, античит, лицензирование) и для исследований безопасности на своих устройствах. Абсолютной детекции не существует: достаточно мотивированный атакующий с кастомным ядром обойдёт любой user-space чек. Используйте Vroot Checker как **сигнал риска**, а не как единственный барьер, и всегда комбинируйте с серверной проверкой (Play Integrity API / собственная аттестация).

Лицензия: MIT.
