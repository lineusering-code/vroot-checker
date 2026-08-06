# Vroot Checker

An Android diagnostics tool that answers one question in detail: **is this device or process environment modified?**

Most root checkers return a single boolean and leave you guessing. Vroot Checker runs 18 independent probes producing 81 individual signals, shows what fired, how it was detected, what evidence was collected, and why it matters - then lets you export the whole thing, including the full scan log, as JSON or Markdown.

[![Build](https://github.com/lineusering-code/vroot-checker/actions/workflows/build.yml/badge.svg)](https://github.com/lineusering-code/vroot-checker/actions)

---

## What it detects

Signals are grouped into four buckets, each scored independently.

### Root (`Root`)

| Check | id | Looks at |
|---|---|---|
| Root binaries | `root.binaries` | `su`, `magisk`, `busybox`, `resetprop` across every `PATH` entry and known install locations, via native `access()` rather than `File.exists()` |
| Root managers | `root.manager` | Magisk / KernelSU / APatch packages, data directories, sockets and mount traces |
| Mount points | `root.mounts` | `overlayfs` / `tmpfs` over real system mounts, `magisk` markers in `/proc/self/mountinfo` |
| System properties | `root.props` | `ro.debuggable`, `ro.secure`, `service.adb.root`, `ro.build.selinux` and friends |
| SELinux | `root.selinux` | enforcing state, policy file readability, permissive domains |
| Installed packages | `root.packages` | root managers, hiding frameworks, privileged ADB helpers such as Shizuku |
| Writable system | `root.writable` | actual write attempts into `/system`, `/vendor`, `/product` and other read-only trees |

### Virtualization (`Virtual`)

| Check | id | Looks at |
|---|---|---|
| Emulator artifacts | `virt.emulator` | goldfish/ranchu devices, QEMU pipes, emulator-only files and TTY drivers |
| Build and fingerprint | `virt.build` | `generic`, `test-keys`, `sdk_gphone` tokens, internal fingerprint consistency |
| Hypervisor and CPU | `virt.hypervisor` | `hypervisor` CPU flag, `/proc/cpuinfo` shape, guest-only device nodes, x86 on a phone |
| Hardware and sensors | `virt.hardware` | sensor and camera inventory, battery, telephony, MAC OUI, uptime, thermal zones |
| Clones and containers | `virt.appclone` | data-directory mismatch, unusual UID range, foreign package data in `maps`, cgroup shape |

### Hooking (`Hooking`)

| Check | id | Looks at |
|---|---|---|
| Frida | `hook.frida` | server binaries, gadget libraries mapped into the process, default ports, agent thread names |
| Xposed / LSPosed | `hook.xposed` | loadable framework classes, framework files, injected stack frames, mapped hook libraries |
| Native hooks | `hook.native` | inline hook prologues in libc, anonymous executable mappings, deleted mappings, foreign libraries |
| Tracers and debuggers | `debug.tracer` | `TracerPid`, JDWP threads, a `ptrace` self-attach probe, seccomp mode |
| Developer mode and ADB | `debug.adb` | `adb_enabled`, developer options, mock location, `service.adb.root`, ADB over TCP |

### Integrity (`Integrity`)

| Check | id | Looks at |
|---|---|---|
| Application integrity | `integrity.app` | debuggable flag, signing certificate, installer package, foreign native libraries, APK location |

---

## How scoring works

A single suspicious file should not scream "rooted", and twenty weak hints should not stay silent. So the score is not a sum.

1. Every triggered signal contributes `severity.weight * confidence / 100`. Weights: `INFO 0`, `LOW 8`, `MEDIUM 18`, `HIGH 32`, `CRITICAL 55`.
2. Each bucket's raw total is squashed into 0-100 with `100 * (1 - exp(-raw / 70))`, so the first real finding moves the needle a lot and the tenth barely does.
3. The overall score is the worst bucket plus a geometrically decaying share of the rest - a device that is rooted *and* hooked scores higher than one that is only rooted, without the buckets simply adding up.
4. Thresholds: `<15` **Clean**, `<35` **Suspicious**, `<65` **Compromised**, otherwise **Hostile**.
5. A `CRITICAL` signal can force **Hostile**, but only with corroboration: two critical hits from two different probes, or one critical hit on a device already scoring 35+. One lonely critical signal cannot hijack the verdict.

Every probe runs with its own timeout (1.8 s by default) on a background dispatcher. A probe that hangs or throws is recorded as `timed out` / `failed` and never takes the scan down with it.

---

## Reading the output

- **Overview** - verdict, overall risk, per-bucket bars, and every triggered signal as a card with severity, evidence, detection method, confidence and a plain-language explanation of why it matters.
- **Log** - the full scan log with level filters (`TRC`, `INF`, `HIT`, `OK`, `WRN`, `ERR`), full-text search and monospace formatting. Every probe start, every raw snapshot and every decision is in there.
- **Settings** - language and per-check switches.
- **About** - version, author and repository links.

---

## Export

Six routes, all carrying the complete log:

| Format | Copy | Share | Save |
|---|---|---|---|
| JSON | clipboard | share sheet | `Downloads/` |
| Markdown | clipboard | share sheet | `Downloads/` |

Plus **copy log only** as plain text. Files are named `vroot-<model>-<yyyyMMdd-HHmmss>.<ext>`.

**Markdown** is written to be pasted straight into an issue: verdict badge, device table, risk bars, key findings, per-check detail and a collapsed full log.

**JSON** (schema `2`) is written to be parsed. Localized labels always sit next to stable machine codes, so a translated report stays queryable:

```jsonc
{
  "schema": 2,
  "language": "en",
  "scan": { "verdict": { "code": "SUSPICIOUS", "title": "Suspicious" }, "totalScore": 29 },
  "probes": [{
    "id": "debug.adb", "name": "Developer mode and ADB",
    "bucket": "HOOK", "bucketTitle": "Hooking",
    "signals": [{
      "id": "debug.adb.adb_enabled", "triggered": true,
      "severityCode": "LOW", "severity": "Low",
      "evidence": [{ "key": "adb_enabled", "value": "1" }]
    }]
  }]
}
```

Useful queries:

```bash
# everything that fired, with evidence
jq -r '.probes[].signals[] | select(.triggered) |
  "\(.severityCode)\t\(.id)\t\([.evidence[]? | "\(.key)=\(.value)"] | join(" | "))"' report.json

# risk per bucket
jq -r '.buckets[] | "\(.bucket) raw=\(.raw) norm=\(.normalized) hits=\(.hits)"' report.json

# only high-severity findings
jq -r '.probes[].signals[] | select(.triggered and (.severityCode | IN("HIGH","CRITICAL"))) | .id' report.json
```

---

## Language

English and Russian, switchable in **Settings** at runtime - no restart, and independent of the system locale. The first launch follows the device locale, after that your explicit choice wins.

The language applies to exports too: a Markdown or JSON report is rendered in the selected language even if the device is running another one. Strings live in a typed catalogue (`core/i18n/UiStrings.kt`), so adding a string breaks compilation until every language provides it - a translation can never silently fall back to a blank label.

Adding a language means adding one file with the catalogue plus signal-text maps, and one enum entry in `Lang`. Nothing else has to change.

---

## Choosing which checks run

Every one of the 18 probes can be switched off in **Settings**. A disabled probe is not executed at all - it does not appear in the log, does not contribute to any bucket and cannot influence the verdict. The log states how many checks were queued and which were skipped, so an exported report never looks unexplainably empty.

Useful when a probe is slow on a particular device, when you want to isolate what a single check reports, or when a check is noisy on your hardware.

---

## Implementation notes

- **Kotlin + Jetpack Compose**, Material 3, dynamic color, dark theme by default. Vector icons only, one consistent Android-style set.
- **Native layer** (`vroot_native.c`) for the checks that must not go through the framework: raw `syscall()` for `faccessat`, direct `/proc` reads, `ptrace` self-attach, `seccomp` mode, `maps` scanning and inline-hook prologue inspection. Framework calls can be hooked; a raw syscall is harder to fake convincingly.
- **No shell by default** where a syscall will do - spawning `sh` is both slower and itself detectable.
- **False positives are treated as bugs.** Path matching is token- and boundary-aware, self-package traces are excluded from stack scans, `/apex` mounts are not treated as tampering, `memfd`/`ashmem` mappings are not treated as injected code, and a `user` build with `release-keys` is not penalised for looking ordinary.
- Findings that are informative but not evidence of tampering (Shizuku present, unusual CPU topology, installer package) are reported as `INFO` with weight 0: visible in the report, invisible to the score.

### Build

```bash
git clone https://github.com/lineusering-code/vroot-checker
cd vroot-checker
./gradlew assembleDebug
```

`minSdk 26`, `compileSdk`/`targetSdk 35`, JVM target 17, AGP 8.9.1, Kotlin 2.1.20, Gradle 8.11.1, CMake 3.22.1. No third-party runtime dependencies beyond AndroidX and Compose.

### Layout

```
core/            engine, models, scoring, log
core/i18n/       language catalogues and translation maps
probes/          18 probes + shared path helpers
report/          JSON, Markdown and export routes
ui/              Compose screens, components, theme
src/main/cpp/    native helpers
```

---

## Scope and honesty

This is a **diagnostics** tool, not an anti-tamper solution. It tells a human what the environment looks like; it does not try to stop anyone. Any userspace detector can be defeated by a sufficiently determined kernel-level hider - the goal here is to make that cost visible and to explain every conclusion instead of asserting it.

Signals are reported with a confidence value precisely because some of them are inherently ambiguous. Read the evidence, not just the verdict.

---

## Author and license

Built by [lineusering-code](https://github.com/lineusering-code).
Repository: <https://github.com/lineusering-code/vroot-checker> - [issues](https://github.com/lineusering-code/vroot-checker/issues) - [releases](https://github.com/lineusering-code/vroot-checker/releases)

MIT.
