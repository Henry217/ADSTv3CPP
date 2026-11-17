# ADST V3 (v3 C++ rewrite)

A tool for counting antivirus detections. It first records the MD5 of every file in a sample folder;
after the antivirus has processed the folder, it compares them again. A file that is gone counts as
"deleted", a file whose content changed counts as "cleaned", and the detection rate is calculated.

Written in C++17 using only the Win32 API, with no third-party dependencies; MD5 is computed with the
system BCrypt library.

## Build

MinGW-w64 (statically linked; the resulting exe runs on its own):

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

You can also open this folder in Visual Studio (as a CMake project) and build it there. The output is
`build/ADST.exe`.

## Layout

- `src/scanner.*`: scanning, hashing, comparison and report generation (independent of the UI)
- `src/main.cpp`: Win32 user interface
- `res/`: icon, manifest, version information



# ADST V3（v3 C++重构版）

杀毒软件检测数目统计工具：先记录样本文件夹中每个文件的 MD5，杀毒软件处理后再对比——
文件消失计为“删除”，内容变化计为“清除”，并算出检出率。

纯 Win32 API + C++17 实现，无第三方依赖；MD5 使用系统 BCrypt。

## 构建

MinGW-w64（静态链接，生成的 exe 可直接运行）：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

也可以用 Visual Studio 打开本文件夹（CMake 项目）构建。产物为 `build/ADST.exe`。

## 目录

- `src/scanner.*`：扫描、哈希、对比、报告（与界面无关）
- `src/main.cpp`：Win32 界面
- `res/`：图标、清单、版本信息


