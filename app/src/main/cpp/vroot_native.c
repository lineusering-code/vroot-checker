/*
 * Vroot Checker — нативный слой диагностики.
 *
 * Задача: не доверять Java. Всё, что можно, читаем прямыми системными
 * вызовами, чтобы Xposed/LSPosed-хуки на java.io.File и SystemProperties
 * не подсовывали нам красивую картинку.
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/system_properties.h>

#define EXPORT __attribute__((visibility("default")))
#define CLS(name) Java_dev_vroot_checker_core_util_NativeBridge_##name

#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif

static int raw_faccessat(const char *path) {
#ifdef SYS_faccessat
    return (int) syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0);
#else
    return access(path, F_OK);
#endif
}

/*
 * Номер stat-вызова зависит от ABI: на arm64/x86_64 ядро знает только
 * newfstatat, а у 32-битных это fstatat64 с другой раскладкой struct stat.
 * Поэтому сырой syscall дёргаем только там, где это безопасно,
 * иначе берём обёртку libc.
 */
static int raw_stat(const char *path, struct stat *st) {
#if (defined(__aarch64__) || defined(__x86_64__)) && defined(SYS_newfstatat)
    return (int) syscall(SYS_newfstatat, AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
#else
    return fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
#endif
}

static int raw_open(const char *path) {
#ifdef SYS_openat
    return (int) syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
#else
    return open(path, O_RDONLY | O_CLOEXEC);
#endif
}

/* ------------------------------------------------------------------ */

EXPORT JNIEXPORT jboolean JNICALL
CLS(nativeAccess)(JNIEnv *env, jobject thiz, jstring jpath) {
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return JNI_FALSE;

    int ok = (raw_faccessat(path) == 0);
    if (!ok) {
        /* second channel: stat() — иногда access() врёт из-за SELinux */
        struct stat st;
        ok = (raw_stat(path, &st) == 0);
    }

    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return ok ? JNI_TRUE : JNI_FALSE;
}

EXPORT JNIEXPORT jstring JNICALL
CLS(nativeReadFile)(JNIEnv *env, jobject thiz, jstring jpath, jint maxBytes) {
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return NULL;

    int fd = raw_open(path);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    if (fd < 0) return NULL;

    size_t cap = (size_t) (maxBytes > 0 ? maxBytes : 65536);
    char *buf = (char *) malloc(cap + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }

    size_t total = 0;
    ssize_t n;
    while (total < cap && (n = read(fd, buf + total, cap - total)) > 0) total += (size_t) n;
    buf[total] = '\0';
    close(fd);

    jstring result = (*env)->NewStringUTF(env, buf);
    free(buf);
    return result;
}

EXPORT JNIEXPORT jstring JNICALL
CLS(nativeGetProp)(JNIEnv *env, jobject thiz, jstring jkey) {
    const char *key = (*env)->GetStringUTFChars(env, jkey, NULL);
    char value[PROP_VALUE_MAX + 1];
    memset(value, 0, sizeof(value));
    if (key) __system_property_get(key, value);
    if (key) (*env)->ReleaseStringUTFChars(env, jkey, key);
    return (*env)->NewStringUTF(env, value);
}

EXPORT JNIEXPORT jint JNICALL
CLS(nativeTracerPid)(JNIEnv *env, jobject thiz) {
    int fd = raw_open("/proc/self/status");
    if (fd < 0) return -1;

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = strstr(buf, "TracerPid:");
    if (!p) return -1;
    return (int) strtol(p + 10, NULL, 10);
}

/* 0 — мы смогли прицепиться к себе (значит никто не трассирует),
   1 — attach отклонён (кто-то уже держит нас), -1 — неизвестно */
EXPORT JNIEXPORT jint JNICALL
CLS(nativePtraceSelfTest)(JNIEnv *env, jobject thiz) {
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        pid_t parent = getppid();
        int res = (int) ptrace(PTRACE_ATTACH, parent, NULL, NULL);
        if (res == 0) {
            waitpid(parent, NULL, 0);
            ptrace(PTRACE_DETACH, parent, NULL, NULL);
            _exit(0);
        }
        _exit(1);
    }

    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status) == 0 ? 0 : 1;
}

EXPORT JNIEXPORT jint JNICALL
CLS(nativeSeccompMode)(JNIEnv *env, jobject thiz) {
    int mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return mode < 0 ? -1 : mode;
}

EXPORT JNIEXPORT jobjectArray JNICALL
CLS(nativeMapsScan)(JNIEnv *env, jobject thiz, jobjectArray jneedles) {
    jsize count = (*env)->GetArrayLength(env, jneedles);

    char **needles = (char **) calloc((size_t) count, sizeof(char *));
    jstring *refs = (jstring *) calloc((size_t) count, sizeof(jstring));
    if (!needles || !refs) {
        free(needles);
        free(refs);
        return (*env)->NewObjectArray(env, 0, (*env)->FindClass(env, "java/lang/String"), NULL);
    }

    for (jsize i = 0; i < count; i++) {
        refs[i] = (jstring) (*env)->GetObjectArrayElement(env, jneedles, i);
        needles[i] = (char *) (*env)->GetStringUTFChars(env, refs[i], NULL);
    }

    char *found[64];
    int foundCount = 0;

    int fd = raw_open("/proc/self/maps");
    if (fd >= 0) {
        FILE *f = fdopen(fd, "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f) && foundCount < 64) {
                for (jsize i = 0; i < count; i++) {
                    if (needles[i] && strcasestr(line, needles[i])) {
                        size_t len = strlen(line);
                        if (len && line[len - 1] == '\n') line[len - 1] = '\0';
                        found[foundCount++] = strdup(line);
                        break;
                    }
                }
            }
            fclose(f);
        } else {
            close(fd);
        }
    }

    for (jsize i = 0; i < count; i++) {
        (*env)->ReleaseStringUTFChars(env, refs[i], needles[i]);
    }
    free(needles);
    free(refs);

    jclass strCls = (*env)->FindClass(env, "java/lang/String");
    jobjectArray out = (*env)->NewObjectArray(env, foundCount, strCls, NULL);
    for (int i = 0; i < foundCount; i++) {
        jstring s = (*env)->NewStringUTF(env, found[i]);
        (*env)->SetObjectArrayElement(env, out, i, s);
        (*env)->DeleteLocalRef(env, s);
        free(found[i]);
    }
    return out;
}

/*
 * Грубая, но рабочая проверка inline-хука: смотрим первые байты функции.
 * Практически все hook-движки (Dobby, Frida-gum, Substrate, xHook)
 * затирают пролог трамплином вида «загрузить адрес → безусловный переход».
 *
 *  1 — пролог выглядит пропатченным
 *  0 — выглядит нормально
 * -1 — не смогли проверить
 */
EXPORT JNIEXPORT jint JNICALL
CLS(nativeInlineHookCheck)(JNIEnv *env, jobject thiz, jstring jlib, jstring jsym) {
    const char *lib = (*env)->GetStringUTFChars(env, jlib, NULL);
    const char *sym = (*env)->GetStringUTFChars(env, jsym, NULL);
    jint verdict = -1;

    void *handle = dlopen(lib, RTLD_NOW | RTLD_NOLOAD);
    if (!handle) handle = dlopen(lib, RTLD_NOW);
    if (handle) {
        void *addr = dlsym(handle, sym);
        if (addr) {
            const unsigned char *code = (const unsigned char *) addr;
#if defined(__aarch64__)
            unsigned int i0 = *(const unsigned int *) code;
            unsigned int i1 = *(const unsigned int *) (code + 4);
            /* b / bl (0x14000000, 0x94000000), ldr x16 + br x16 (0xd61f0200) */
            if ((i0 & 0xfc000000u) == 0x14000000u ||
                (i0 & 0xfc000000u) == 0x94000000u ||
                i1 == 0xd61f0200u || i1 == 0xd61f0220u) {
                verdict = 1;
            } else {
                verdict = 0;
            }
#elif defined(__arm__)
            unsigned int i0 = *(const unsigned int *) code;
            /* ldr pc, [pc, #-4]  == 0xe51ff004 ; b imm == 0xea…  */
            if (i0 == 0xe51ff004u || (i0 & 0x0f000000u) == 0x0a000000u) verdict = 1;
            else verdict = 0;
#elif defined(__x86_64__) || defined(__i386__)
            /* jmp rel32 (0xE9) / push+ret / mov rax,imm64 + jmp rax (0x48 0xB8) */
            if (code[0] == 0xE9 || code[0] == 0x68 ||
                (code[0] == 0x48 && code[1] == 0xB8) || code[0] == 0xFF) {
                verdict = 1;
            } else {
                verdict = 0;
            }
#endif
        }
        dlclose(handle);
    }

    (*env)->ReleaseStringUTFChars(env, jlib, lib);
    (*env)->ReleaseStringUTFChars(env, jsym, sym);
    return verdict;
}

EXPORT JNIEXPORT jint JNICALL
CLS(nativeOpenDirCount)(JNIEnv *env, jobject thiz, jstring jpath) {
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    int count = -1;
    DIR *d = opendir(path);
    if (d) {
        count = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
        }
        closedir(d);
    }
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return count;
}

EXPORT JNIEXPORT jstring JNICALL
CLS(nativeReadlink)(JNIEnv *env, jobject thiz, jstring jpath) {
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    char buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    if (n < 0) return NULL;
    buf[n] = '\0';
    return (*env)->NewStringUTF(env, buf);
}

EXPORT JNIEXPORT jint JNICALL
CLS(nativeUid)(JNIEnv *env, jobject thiz) {
    return (jint) getuid();
}
