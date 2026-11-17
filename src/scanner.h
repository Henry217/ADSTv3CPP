// 扫描 / 哈希 / 对比逻辑，与界面无关。
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace adst {

using Md5 = std::array<std::uint8_t, 16>;

// 计算文件 MD5。读取失败或被取消时返回 std::nullopt。
// 以共享读写删除方式打开，不会妨碍杀毒软件处理该文件。
std::optional<Md5> HashFile(const std::wstring& path, const std::atomic<bool>* cancel = nullptr);

std::wstring ToHex(const Md5& md5);

// 规范化为绝对路径（失败时原样返回）。
std::wstring FullPath(const std::wstring& path);

bool IsDirectory(const std::wstring& path);

struct FileRecord {
    std::wstring path;
    Md5 md5{};
};

enum class Phase { Counting, Hashing, Comparing };

// done/total：Counting 阶段 total 为 0（总数未知），done 为已发现的文件数。
using ProgressFn = std::function<void(Phase phase, std::size_t done, std::size_t total)>;

struct ScanResult {
    std::vector<FileRecord> files;
    std::size_t unreadable = 0;   // 无法读取、已跳过的文件
    std::size_t dirErrors = 0;    // 无法枚举的目录
    bool cancelled = false;
};

// 递归扫描文件夹，记录每个文件的 MD5 作为基线。
// 不跟随符号链接 / 目录联接，避免循环。
ScanResult Scan(const std::wstring& root, const std::atomic<bool>& cancel, const ProgressFn& progress);

struct Stats {
    std::size_t total = 0;       // 基线文件总数
    std::size_t deleted = 0;     // 文件已不存在
    std::size_t cleaned = 0;     // 内容已改变
    std::size_t untouched = 0;   // 未变化
    std::size_t unreadable = 0;  // 存在但无法读取（可能被占用或隔离中）
    bool cancelled = false;

    std::size_t detected() const { return deleted + cleaned; }
};

// 将当前文件状态与基线对比。
Stats Compare(const std::vector<FileRecord>& baseline, const std::atomic<bool>& cancel,
              const ProgressFn& progress);

// 生成统计报告文本（行尾为 \r\n，可直接放入编辑框或写入文件）。
std::wstring FormatReport(const Stats& stats, const std::wstring& version);

}  // namespace adst
