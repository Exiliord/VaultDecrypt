# 🔓 VaultDecrypt

**Decrypt photos hidden by APK Vault and similar "vault" apps.**

Many so-called "vault" apps on Android don't actually encrypt your photos — they just XOR the file header with a single byte (`0x05`) and slap on a custom magic header (`FADAFAE5` or `FADDFAE5`). This tool reverses that in milliseconds.

## ⚠️ Disclaimer

This tool is intended for **recovering your own photos** from vault apps you've used. Do not use it to access files that don't belong to you.

## 📦 What's Included

| Platform | File | Description |
|----------|------|-------------|
| **Android** | `VaultDecrypt.apk` | Android app — pick `.bin` files and decrypt |
| **Windows** | `VaultDecrypt.exe` | Windows CLI tool — scans folder for `.bin` files |
| **Source** | `android/` + `windows/` | Full source code |

## 🚀 Quick Start

### Android
1. Install `VaultDecrypt.apk` (enable "Unknown sources" if needed)
2. Open the app → grant storage permissions
3. Tap **"Select .bin file"** and navigate to your vault folder
4. Photos are saved to `Pictures/VaultDecrypt/`

You can also open `.bin` files directly from your file explorer → **Open with → VaultDecrypt**.

### Windows
1. Place `VaultDecrypt.exe` in the folder containing `.bin` files
2. Double-click to run
3. All `.bin` files in the folder will be decrypted to `.jpg`

Or from command line:
```
VaultDecrypt.exe C:\path\to\vault\folder
```

## 🔬 How It Works

Vault apps using the OCLC format store photos like this:

```
[FADAFAE5 or FADDFAE5 header] [XOR'd JPEG header] [Raw JPEG data from SOF2 to EOI]
```

The "encryption" is simply:
1. Take a normal JPEG file
2. XOR the first N bytes (up to the SOF2 marker) with `0x05`
3. Prepend a 4-byte magic header (`FADAFAE5` / `FADDFAE5`)
4. Rename to `.bin`

This tool:
1. Detects the magic header
2. Finds the SOF2 marker in the raw data
3. XORs the header back to restore the original JPEG header
4. Combines it with the raw JPEG body
5. Saves as a standard `.jpg`

## 📁 Supported Formats

| Magic Header | XOR Key | Status |
|-------------|---------|--------|
| `FA DA FA E5` | `0x05` | ✅ Supported |
| `FA DD FA E5` | `0x05` | ✅ Supported |

## 🛠 Building from Source

### Android
```bash
cd android/
./gradlew assembleRelease
```
Output: `android/app/build/outputs/apk/release/app-release-unsigned.apk`

Requirements: Android SDK 34, Java 17, Gradle 8.4+

### Windows
```bash
# Cross-compile from Linux:
x86_64-w64-mingw32-gcc -O2 -static -o VaultDecrypt.exe windows/vault_decrypt.c

# Or compile natively with MSVC/MinGW on Windows
```

## 📸 Screenshots

*(Coming soon)*

## 📄 License

MIT License — use it however you want.

## 🙏 Credits

Built by **Alex** (OpenClaw) — because "vault" apps shouldn't get away with calling XOR "encryption" 💀
