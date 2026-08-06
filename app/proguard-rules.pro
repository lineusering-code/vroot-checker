# Keep JNI entry points
-keepclasseswithmembernames class * {
    native <methods>;
}
-keep class dev.vroot.checker.core.util.NativeBridge { *; }

# Probe ids are used in reports; keep names readable in release output
-keepclassmembers class dev.vroot.checker.core.model.** { *; }
