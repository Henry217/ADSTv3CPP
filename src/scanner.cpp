#include "scanner.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <memory>

namespace adst {
namespace {

}  // namespace

std::wstring FullPath(const std::wstring& path) {
    DWORD n = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (n == 0) return path;
    std::wstring out(n, L'\0');
    n = GetFullPathNameW(path.c_str(), n, out.data(), nullptr);
    if (n == 0) return path;
    out.resize(n);
    // 去掉末尾多余的反斜杠（盘符根目录 "C:\" 除外）
    while (out.size() > 3 && out.back() == L'\\') out.pop_back();
    return out;
}

namespace {

// 规范化为绝对路径并加 \\?\ 前缀，以支持超过 MAX_PATH 的路径。
// （\\?\ 路径不会再被系统规范化，所以必须先转成反斜杠绝对路径。）
std::wstring ExtendedPath(const std::wstring& path) {
    if (path.rfind(L"\\\\?\\", 0) == 0) return path;
    std::wstring full = FullPath(path);
    if (full.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + full.substr(2);
    return L"\\\\?\\" + full;
}

struct HandleCloser {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

struct FindCloser {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) FindClose(h);
    }
};
using UniqueFind = std::unique_ptr<void, FindCloser>;

struct HashCloser {
    void operator()(BCRYPT_HASH_HANDLE h) const {
        if (h) BCryptDestroyHash(h);
    }
};
using UniqueHash = std::unique_ptr<void, HashCloser>;

// 进程内共享的 MD5 算法句柄（BCrypt 算法句柄可跨线程使用）。
BCRYPT_ALG_HANDLE Md5Provider() {
    static BCRYPT_ALG_HANDLE alg = [] {
        BCRYPT_ALG_HANDLE h = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_MD5_ALGORITHM, nullptr, 0))) h = nullptr;
        return h;
    }();
    return alg;
}

bool IsDotOrDotDot(const wchar_t* name) {
    return (name[0] == L'.' && name[1] == 0) || (name[0] == L'.' && name[1] == L'.' && name[2] == 0);
}

}  // namespace

bool IsDirectory(const std::wstring& path) {
    if (path.empty()) return false;
    DWORD attr = GetFileAttributesW(ExtendedPath(path).c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::optional<Md5> HashFile(const std::wstring& path, const std::atomic<bool>* cancel) {
    BCRYPT_ALG_HANDLE alg = Md5Provider();
    if (!alg) return std::nullopt;

    UniqueHandle file(CreateFileW(ExtendedPath(path).c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) return std::nullopt;

    BCRYPT_HASH_HANDLE rawHash = nullptr;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &rawHash, nullptr, 0, nullptr, 0, 0))) return std::nullopt;
    UniqueHash hash(rawHash);

    constexpr DWORD kChunk = 1 << 20;
    std::unique_ptr<std::uint8_t[]> buf(new std::uint8_t[kChunk]);
    for (;;) {
        if (cancel && cancel->load(std::memory_order_relaxed)) return std::nullopt;
        DWORD read = 0;
        if (!ReadFile(file.get(), buf.get(), kChunk, &read, nullptr)) return std::nullopt;
        if (read == 0) break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hash.get(), buf.get(), read, 0))) return std::nullopt;
    }

    Md5 out{};
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash.get(), out.data(), static_cast<ULONG>(out.size()), 0)))
        return std::nullopt;
    return out;
}

std::wstring ToHex(const Md5& md5) {
    static const wchar_t kDigits[] = L"0123456789ABCDEF";
    std::wstring s;
    s.reserve(md5.size() * 2);
    for (auto b : md5) {
        s.push_back(kDigits[b >> 4]);
        s.push_back(kDigits[b & 0xF]);
    }
    return s;
}

ScanResult Scan(const std::wstring& root, const std::atomic<bool>& cancel, const ProgressFn& progress) {
    ScanResult result;

    // 第一阶段：枚举所有文件（显式栈，避免深层目录递归爆栈）
    std::vector<std::wstring> paths;
    std::vector<std::wstring> stack{FullPath(root)};
    while (!stack.empty()) {
        if (cancel) { result.cancelled = true; return result; }
        std::wstring dir = std::move(stack.back());
        stack.pop_back();

        WIN32_FIND_DATAW fd;
        UniqueFind find(FindFirstFileExW(ExtendedPath(dir + L"\\*").c_str(), FindExInfoBasic, &fd,
                                         FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH));
        if (find.get() == INVALID_HANDLE_VALUE) {
            ++result.dirErrors;
            continue;
        }
        do {
            if (IsDotOrDotDot(fd.cFileName)) continue;
            std::wstring child = dir;
            if (child.back() != L'\\') child += L'\\';
            child += fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // 不进入符号链接 / 目录联接，防止循环
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) stack.push_back(std::move(child));
            } else {
                paths.push_back(std::move(child));
                if (progress) progress(Phase::Counting, paths.size(), 0);
            }
        } while (FindNextFileW(find.get(), &fd));
    }

    // 第二阶段：逐个计算 MD5
    const std::size_t total = paths.size();
    result.files.reserve(total);
    for (std::size_t i = 0; i < total; ++i) {
        if (cancel) { result.cancelled = true; return result; }
        if (auto md5 = HashFile(paths[i], &cancel)) {
            result.files.push_back({std::move(paths[i]), *md5});
        } else if (cancel) {
            result.cancelled = true;
            return result;
        } else {
            ++result.unreadable;
        }
        if (progress) progress(Phase::Hashing, i + 1, total);
    }
    return result;
}

Stats Compare(const std::vector<FileRecord>& baseline, const std::atomic<bool>& cancel,
              const ProgressFn& progress) {
    Stats st;
    st.total = baseline.size();
    for (std::size_t i = 0; i < baseline.size(); ++i) {
        if (cancel) { st.cancelled = true; return st; }
        const FileRecord& rec = baseline[i];

        DWORD attr = GetFileAttributesW(ExtendedPath(rec.path).c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ++st.deleted;
            else ++st.unreadable;
        } else if (auto md5 = HashFile(rec.path, &cancel)) {
            if (*md5 == rec.md5) ++st.untouched;
            else ++st.cleaned;
        } else if (cancel) {
            st.cancelled = true;
            return st;
        } else {
            ++st.unreadable;
        }
        if (progress) progress(Phase::Comparing, i + 1, baseline.size());
    }
    return st;
}

std::wstring FormatReport(const Stats& s, const std::wstring& version) {
    std::wstring rate = L"N/A";
    if (s.total > 0) {
        wchar_t buf[32];
        std::swprintf(buf, 32, L"%.2f%%", 100.0 * static_cast<double>(s.detected()) / static_cast<double>(s.total));
        rate = buf;
    }
    std::wstring r;
    r += L"程序版本: ADST " + version + L" by henry217\r\n";
    r += L"文件总数: " + std::to_wstring(s.total) + L"\r\n";
    r += L"删除个数: " + std::to_wstring(s.deleted) + L"\r\n";
    r += L"清除个数: " + std::to_wstring(s.cleaned) + L"\r\n";
    r += L"总检出个数: " + std::to_wstring(s.detected()) + L"\r\n";
    r += L"未检出个数: " + std::to_wstring(s.total - s.detected()) + L"\r\n";
    if (s.unreadable > 0)
        r += L"  其中无法读取: " + std::to_wstring(s.unreadable) + L"（文件仍在但被占用或拒绝访问）\r\n";
    r += L"检出率: " + rate + L"\r\n";
    return r;
}

}  // namespace adst
