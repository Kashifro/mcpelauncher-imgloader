/* imgloader.c
Hooks mce::ImageUtils::loadImageFromMemory it substitutes at the two known broken call sites inside LoadingScreen::frameUpdate which are found by scanning
its bytes for `call loadImageFromMemory` and matching ret addr at runtime, every other call, any format passes through untouched
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inlinehook.h"
#include "fallback.h"

static void mlog(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "[imgloader] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
//the mods own dir for placeholder
static const char *mod_dir(void) {
    static char buf[4096] = ".";
    static int done = 0;
    if (!done) {
        Dl_info info;
        if (dladdr((void *)mod_dir, &info) && info.dli_fname) {
            const char *slash = strrchr(info.dli_fname, '/');
            if (slash) {
                size_t n = (size_t)(slash - info.dli_fname);
                if (n >= sizeof(buf)) n = sizeof(buf) - 1;
                memcpy(buf, info.dli_fname, n);
                buf[n] = 0;
            }
        }
        done = 1;
    }
    return buf;
}

//tiny pattern scanner
static int parse_pattern(const char *sig, int16_t *out, int max) {
    int n = 0;
    const char *p = sig;
    while (*p && n < max) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            out[n++] = -1;
            while (*p == '?') p++;
        } else {
            out[n++] = (int16_t)strtol(p, NULL, 16);
            while (*p && *p != ' ') p++;
        }
    }
    return n;
}

static void *scan(const uint8_t *base, size_t size, const int16_t *pat, int patlen) {
    if (patlen <= 0 || (size_t)patlen > size) return NULL;
    for (size_t i = 0; i + (size_t)patlen <= size; i++) {
        int ok = 1;
        for (int j = 0; j < patlen; j++) {
            if (pat[j] != -1 && base[i + j] != (uint8_t)pat[j]) { ok = 0; break; }
        }
        if (ok) return (void *)(base + i);
    }
    return NULL;
}

struct find_ctx { void *base; size_t size; };

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libminecraftpe.so")) return 0;
    struct find_ctx *ctx = (struct find_ctx *)data;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags & PF_X)) {
            ctx->base = (void *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            ctx->size = info->dlpi_phdr[i].p_memsz;
            return 1;
        }
    }
    return 0;
}

static int find_mc_exec_range(void **base, size_t *size) {
    struct find_ctx ctx = {0, 0};
    if (!dlopen("libminecraftpe.so", RTLD_NOLOAD)) return 0;
    if (!dl_iterate_phdr(phdr_cb, &ctx)) return 0;
    *base = ctx.base;
    *size = ctx.size;
    return 1;
}
//26.40 x86_64
static const char *imgloader_sig = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC ? ? ? ? 45 89 CE 4D 89 C5 48 89 CB 41 89 D7";
static const char *frameupdate_sig = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC ? ? ? ? 49 89 FE 64 48 8B 04 25 ? ? ? ? 48 89 45 ? 48 89 B5 ? ? ? ? 4C 8B 66";

static uint8_t *fallback_bytes = NULL;
static size_t fallback_length = 0;

static void load_placeholder(void) {
    char path[4200];
    snprintf(path, sizeof(path), "%s/placeholder.png", mod_dir());
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 8 || sz > 8 * 1024 * 1024) { fclose(f); return; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return; }
    int ok = fread(buf, 1, (size_t)sz, f) == (size_t)sz &&
             buf[0] == 0x89 && buf[1] == 0x50 && buf[2] == 0x4E && buf[3] == 0x47;
    fclose(f);
    if (!ok) { free(buf); return; }
    fallback_bytes = buf;
    fallback_length = (size_t)sz;
}

static const uint8_t *substitute(size_t *out_len) {
    if (fallback_bytes) { *out_len = fallback_length; return fallback_bytes; }
    *out_len = fallback_size;
    return fallback;
}

//ret addre of loadImageFromMemory calls inside LoadingScreen::frameUpdate; 2 expected
#define MAX_CALLSITES 2
static void *loadscreen_callsites[MAX_CALLSITES];
static int loadscreen_callsite_count = 0;

static void find_loadscreen_callsites(const void *fn_start, size_t scan_window, const void *lm_addr) {
    const uint8_t *p = (const uint8_t *)fn_start;
    for (size_t i = 0; i + 5 <= scan_window && loadscreen_callsite_count < MAX_CALLSITES; i++) {
        if (p[i] == 0xE8) { /*rel32 call*/
            int32_t rel;
            memcpy(&rel, &p[i + 1], 4);
            const uint8_t *ret_addr = p + i + 5;
            const uint8_t *tgt = ret_addr + rel;
            if (tgt == (const uint8_t *)lm_addr) {
                loadscreen_callsites[loadscreen_callsite_count++] = (void *)ret_addr;
                mlog("found loading screen call site, return addr %p\n", (void *)ret_addr);
            }
        }
    }
}

static int is_loadscreen_call(void) {
    void *ret = __builtin_return_address(0);
    for (int i = 0; i < loadscreen_callsite_count; i++)
        if (loadscreen_callsites[i] == ret) return 1;
    return 0;
}

typedef int64_t (*load_image_fn)(int64_t, int64_t, int, int64_t, uint64_t, char);
static load_image_fn orig_load_image = NULL;

static int64_t load_image_detour(int64_t a1, int64_t a2, int a3, int64_t a4, uint64_t a5, char a6) {
    if (!orig_load_image) return 0;
    if (is_loadscreen_call()) {
        size_t len = 0;
        const uint8_t *png = substitute(&len);
        return orig_load_image(a1, a2, a3, (int64_t)png, (uint64_t)len, a6);
    }
    return orig_load_image(a1, a2, a3, a4, a5, a6);
}

extern __attribute__((visibility("default"))) void mod_preinit(void) {
    mlog("mod_preinit\n");
}

extern __attribute__((visibility("default"))) void mod_init(void) {
    load_placeholder();

    void *base = NULL;
    size_t size = 0;
    if (!find_mc_exec_range(&base, &size)) {
        mlog("libminecraftpe.so exec range unavailable\n");
        return;
    }

    int16_t pat[64];
    int patlen = parse_pattern(imgloader_sig, pat, 64);
    void *target = scan((const uint8_t *)base, size, pat, patlen);
    if (!target) {
        mlog("loadImageFromMemory signature not found \n");
        return;
    }

    int16_t fu_pat[64];
    int fu_patlen = parse_pattern(frameupdate_sig, fu_pat, 64);
    void *fu_target = scan((const uint8_t *)base, size, fu_pat, fu_patlen);
    if (fu_target) find_loadscreen_callsites(fu_target, 0x1000, target);
    if (loadscreen_callsite_count == 0)
        mlog("warning: no loading screen call sites resolved, hook will be a no-op\n");

    void *orig = NULL;
    hook_handle *h = hook_addr(target, (void *)load_image_detour, &orig, GPWN_X86_64_LONGHOOK);
    if (!h || !orig) {
        mlog("hook install failed at %p\n", target);
        return;
    }
    orig_load_image = (load_image_fn)orig;
    mlog("hooked loadImageFromMemory at %p (%d loading screen call sites)\n", target, loadscreen_callsite_count);
}