package dev.vroot.checker.probes

/** Справочники известных артефактов. Вынесены отдельно, чтобы пробы читались. */
object Signatures {

    val SU_PATHS = listOf(
        "/sbin/su", "/su/bin/su", "/system/bin/su", "/system/xbin/su", "/system/sbin/su",
        "/vendor/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
        "/data/local/bin/su", "/data/local/xbin/su", "/system/bin/.ext/.su", "/system/usr/we-need-root/su",
        "/cache/su", "/dev/su", "/magisk/.core/bin/su", "/sbin/.magisk/su", "/debug_ramdisk/su",
        "/system_ext/bin/su", "/apex/com.android.runtime/bin/su",
    )

    val ROOT_TOOL_PATHS = listOf(
        "/system/xbin/busybox", "/system/bin/busybox", "/data/local/busybox", "/sbin/busybox",
        "/system/xbin/daemonsu", "/system/bin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
        "/system/xbin/supolicy", "/sbin/magisk", "/system/bin/magisk", "/data/adb/magisk/magisk64",
        "/system/bin/resetprop", "/sbin/resetprop", "/system/xbin/ku.sud", "/data/adb/ksud",
        "/system/app/Superuser.apk", "/system/app/SuperSU/SuperSU.apk", "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/",
    )

    val MAGISK_PATHS = listOf(
        "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk.img", "/data/adb/magisk_simple",
        "/data/adb/modules", "/data/adb/post-fs-data.d", "/data/adb/service.d", "/data/adb/lsposed",
        "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock", "/cache/magisk.log",
        "/data/adb/magisk/busybox", "/debug_ramdisk/.magisk", "/sbin/.core", "/init.magisk.rc",
    )

    val KERNELSU_PATHS = listOf(
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu/modules", "/data/adb/ksu/bin",
        "/system/bin/ksud", "/data/adb/ap", "/data/adb/apd", "/data/adb/ap/modules",
    )

    val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk", "io.github.huskydg.magisk", "com.topjohnwu.magisk.delta",
        "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu", "com.noshufou.android.su",
        "com.noshufou.android.su.elite", "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root", "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global", "com.alephzain.framaroot", "com.baidu.easyroot",
        "com.ramdroid.appquarantine", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "org.lsposed.manager", "io.github.lsposed.manager",
        "com.saurik.substrate", "com.formyhm.hideroot", "com.formyhm.hiderootPremium",
        "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree", "com.zachspong.temprootremovejb",
        "com.chelpus.lackypatch", "com.dimonvideo.luckypatcher", "com.android.vending.billing.InAppBillingService.COIN",
        "com.forpda.lp", "me.phh.superuser", "moe.shizuku.privileged.api", "com.oasisfeng.island",
    )

    val CLONE_PACKAGES = listOf(
        "com.lbe.parallel.intl", "com.excelliance.dualaid", "com.ludashi.dualspace",
        "com.jiubang.commerce.gomultiple", "com.polestar.super.clone", "com.cloneapp.parallelspace.dualspace",
        "do.multiple.space", "com.parallel.space.lite", "com.applisto.appcloner",
        "io.va.exposed", "io.virtualapp", "com.qihoo.magic", "com.bly.dkplat",
    )

    val EMULATOR_PACKAGES = listOf(
        "com.bluestacks", "com.bluestacks.appmart", "com.bignox.app", "com.vphone.launcher",
        "com.microvirt.tools", "com.microvirt.launcher", "com.microvirt.download",
        "com.mumu.launcher", "com.mumu.store", "com.ldmnq.launcher3", "com.android.emu.home",
        "com.genymotion.superuser", "com.google.android.launcher.layouts.genymotion",
        "com.redfinger.app", "com.vmos.pro", "com.vmos.app", "com.cyjh.mobileanjian",
    )

    val EMULATOR_FILES = listOf(
        "/dev/socket/qemud", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/goldfish_sync",
        "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace", "/system/bin/qemu-props",
        "/system/bin/qemud", "/init.goldfish.rc", "/ueventd.goldfish.rc", "/init.ranchu.rc",
        "/ueventd.ranchu.rc", "/system/etc/init.goldfish.sh", "/fstab.goldfish", "/fstab.ranchu",
        "/dev/vboxguest", "/dev/vboxuser", "/mnt/prebundledapps/bluestacks.prop.orig",
        "/system/bin/androVM-prop", "/system/bin/microvirt-prop", "/system/lib/libdroid4x.so",
        "/system/bin/windroyed", "/system/bin/nox-prop", "/system/lib/libnoxspeedup.so",
        "/data/.bluestacks.prop", "/system/bin/ttVM-prop", "/dev/socket/genyd", "/dev/socket/baseband_genyd",
    )

    val EMULATOR_BUILD_TOKENS = listOf(
        "generic", "unknown", "emulator", "sdk_gphone", "sdk_google", "google_sdk", "sdk_x86",
        "sdk_arm", "vbox86", "goldfish", "ranchu", "cuttlefish", "vsoc", "android_x86",
        "nox", "bluestacks", "bstk", "ldplayer", "memu", "mumu", "droid4x", "genymotion",
        "andy", "windroy", "remix", "phoenixos", "ttvm", "microvirt", "vmos", "redfinger",
    )

    val HOOK_LIB_TOKENS = listOf(
        "frida", "frida-agent", "frida-gadget", "gum-js-loop", "gmain", "linjector",
        "libsubstrate", "substrate", "libdobby", "dobby", "libxposed", "xposed",
        "liblspd", "lspd", "lsplant", "riru", "zygisk", "libsandhook", "libwhale",
        "libepic", "libyahfa", "shadowhook", "bhook", "xhook", "libmemtrack_real",
    )

    val XPOSED_PATHS = listOf(
        "/system/framework/XposedBridge.jar", "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so", "/system/xposed.prop", "/data/adb/lspd",
        "/data/adb/lspd/config", "/data/misc/riru", "/data/adb/riru", "/data/adb/modules/riru-core",
        "/data/adb/modules/zygisk_lsposed", "/system/bin/app_process_xposed",
    )

    val XPOSED_CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.IXposedHookLoadPackage",
        "org.lsposed.lspd.core.Main",
        "com.saurik.substrate.MS",
    )

    val FRIDA_PATHS = listOf(
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-gadget.so", "/data/local/tmp/gadget-config.json",
        "/sdcard/frida-server", "/system/bin/frida-server",
    )

    /** Стандартные порты Frida (27042 / 27043) в hex для /proc/net/tcp. */
    val FRIDA_PORTS_HEX = listOf("69A2", "69A3")

    val WRITABLE_SYSTEM_DIRS = listOf("/system", "/system/bin", "/system/xbin", "/vendor/bin", "/product", "/etc", "/")
}
