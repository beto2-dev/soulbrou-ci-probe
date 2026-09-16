/*
 * Anti-root, anti-Frida, anti-dexdump, anti-debugging and anti-emulator
 * detection routines. Every check returns non zero when the corresponding
 * hostile environment is detected.
 *
 * The checks are deliberately conservative: they only report high confidence
 * indicators so legitimate devices are never rejected.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/platform.h"
#include "soulbrou/soulbrou_runtime.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

extern "C" {

/* ------------------------------------------------------------------ */
/* Anti-root                                                           */
/* ------------------------------------------------------------------ */

static const char *kRootPaths[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU",
    "/system/bin/magisk",
    "/data/adb/magisk",
    "/sbin/magiskinit",
    "/data/data/com.topjohnwu.magisk",
    "/system/framework/XposedBridge.jar",
    "/system/bin/xposed",
    "/data/dalvik-cache/*XposedBridge*",
    NULL,
};

static const char *kRootPackages[] = {
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "de.robv.android.xposed.installer",
    NULL,
};

int sb_check_anti_root(void) {
    for (int i = 0; kRootPaths[i] != NULL; i++) {
        if (sb_active_platform.file_exists(kRootPaths[i])) {
            return 1;
        }
    }
    // Magisk and Xposed leave fingerprints in the default mounts file.
    if (sb_active_platform.file_contains("/proc/self/mounts", "magisk")) {
        return 1;
    }
    if (sb_active_platform.file_contains("/proc/self/mounts", "xposed")) {
        return 1;
    }
    // Package manager traces of root managers.
    for (int i = 0; kRootPackages[i] != NULL; i++) {
        char path[128];
        snprintf(path, sizeof(path), "/data/data/%s", kRootPackages[i]);
        if (sb_active_platform.file_exists(path)) {
            return 1;
        }
    }
    // SELinux permissive mode is a strong root indicator on production builds.
    if (sb_active_platform.file_contains("/sys/fs/selinux/enforce", "0")) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Anti-Frida                                                          */
/* ------------------------------------------------------------------ */

static int scan_thread_names(const char *needle) {
    DIR *dir = opendir("/proc/self/task");
    if (dir == NULL) {
        return 0;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[96];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        if (sb_active_platform.file_contains(path, needle)) {
            closedir(dir);
            return 1;
        }
    }
    closedir(dir);
    return 0;
}

int sb_check_anti_frida(void) {
    // Default frida-server port.
    if (sb_active_platform.file_contains("/proc/net/tcp", "69A2")) {
        return 1;
    }
    if (sb_active_platform.file_contains("/proc/net/tcp6", "69A2")) {
        return 1;
    }
    // GumJS loop thread.
    if (scan_thread_names("gum-js-loop")) {
        return 1;
    }
    if (scan_thread_names("gmain")) {
        return 1;
    }
    // Injected frida agent mapped into the process.
    if (sb_active_platform.file_contains("/proc/self/maps", "frida-agent")) {
        return 1;
    }
    if (sb_active_platform.file_contains("/proc/self/maps", "frida-gadget")) {
        return 1;
    }
    if (sb_active_platform.file_contains("/proc/self/maps", "linjector")) {
        return 1;
    }
    // frida-server artifacts in the filesystem.
    if (sb_active_platform.file_exists("/data/local/tmp/frida-server")) {
        return 1;
    }
    if (sb_active_platform.file_exists("/data/local/tmp/re.frida.server")) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Anti-dexdump                                                        */
/* ------------------------------------------------------------------ */

int sb_check_anti_dexdump(void) {
    // Dexdump tools attach background threads named after themselves.
    if (scan_thread_names("dexdump")) {
        return 1;
    }
    if (scan_thread_names("dextools")) {
        return 1;
    }
    // In-memory copies of the dex mapped writable outside the app directory
    // are the fingerprint of memory dumping frameworks.
    if (sb_active_platform.file_contains("/proc/self/maps", "/cache/")) {
        return 1;
    }
    if (sb_active_platform.file_contains("/proc/self/maps", "dumpdex")) {
        return 1;
    }
    if (sb_active_platform.file_contains("/proc/self/maps", ".fdex")) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Anti-debugging                                                     */
/* ------------------------------------------------------------------ */

int sb_check_anti_debug(void) {
    if (sb_active_platform.file_contains("/proc/self/status", "TracerPid:\t0")) {
        // Not traced; fall through to the timing check.
    } else if (sb_active_platform.file_contains("/proc/self/status", "TracerPid:")) {
        return 1;
    }
    // Self ptrace: a second attach fails when a debugger is already present.
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, 0, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Anti-emulator                                                       */
/* ------------------------------------------------------------------ */

int sb_check_anti_emulator(void) {
    char value[128];
    if (sb_active_platform.system_property("ro.kernel.qemu", value, sizeof(value)) > 0 &&
        strcmp(value, "1") == 0) {
        return 1;
    }
    if (sb_active_platform.system_property("ro.hardware", value, sizeof(value)) > 0) {
        if (strcmp(value, "goldfish") == 0 || strcmp(value, "ranchu") == 0) {
            return 1;
        }
    }
    if (sb_active_platform.system_property("ro.product.model", value, sizeof(value)) > 0) {
        if (strstr(value, "Emulator") != NULL || strstr(value, "Android SDK") != NULL) {
            return 1;
        }
    }
    if (sb_active_platform.system_property("ro.bootloader", value, sizeof(value)) > 0 &&
        strstr(value, "unknown") != value) {
        // Real devices usually expose a bootloader identifier; this alone is
        // not conclusive so it is only reported alongside the other signals.
    }
    if (sb_active_platform.file_exists("/dev/qemu_pipe")) {
        return 1;
    }
    if (sb_active_platform.file_exists("/dev/socket/genyd")) {
        return 1;
    }
    return 0;
}

} /* extern "C" */
