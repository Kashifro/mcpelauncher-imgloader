# make NDK=/path/to/android-ndk
# or export ANDROID_NDK_HOME or ANDROID_NDK_ROOT and just run `make`.

NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
API ?= 24

ifeq ($(strip $(NDK)),)
$(error Set NDK=/path/to/android-ndk, or export ANDROID_NDK_HOME / ANDROID_NDK_ROOT)
endif

HOST_TAG := $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
CC := $(NDK)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin/x86_64-linux-android$(API)-clang

GPWN := third_party/gamepwnage
BUILD := build
OUT := $(BUILD)/libimgloader.so

SRCS := src/imgloader.c $(GPWN)/hook86.c $(GPWN)/inlinehook.c $(GPWN)/mem.c $(GPWN)/proc.c $(GPWN)/nop.c
OBJS := $(SRCS:%.c=$(BUILD)/%.o)

CFLAGS := -std=c11 -fPIC -fvisibility=hidden -Os -ffunction-sections -fdata-sections -I$(GPWN)
LDFLAGS := -shared -Wl,--gc-sections -Wl,-z,nodelete -Wl,--as-needed -Wl,--version-script=linker.ld -Wl,--strip-all

.PHONY: all clean
all: $(OUT)

$(OUT): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $^ $(LDFLAGS) -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)
