# imgloader

a minimal mod for mcpelauncher-linux that silences the endless
"Image failed to load from memory" log spam by Making it so that we can load the image

Drop `placeholder.png` next to the mod for a real substitute; otherwise an
embedded image reminding you of its abscense is shown.

## Building

Prerequisites: Android NDK.

​```bash
make NDK=/path/to/ndk
​```

Output: `build/libimgloader.so`

## Installing

Copy `libimgloader.so` into mcpelauncher's `mods/` directory.