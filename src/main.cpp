// ADST V3 — 杀毒软件检测数目统计工具（v3 C++重构版，Win32）
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <shellapi.h>
#include <shobjidl.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "resource.h"
#include "scanner.h"

namespace {

enum : UINT {
    WM_APP_PROGRESS = WM_APP + 1,
    WM_APP_SCAN_DONE,
    WM_APP_STATS_DONE,
    WM_APP_AMST_DONE,
};

enum : int {
    IDC_TAB = 1000,
    IDC_PATH_LABEL,
    IDC_PATH,
    IDC_BROWSE,
    IDC_SCAN,
    IDC_SCAN_CANCEL,
    IDC_SCAN_PROGRESS,
    IDC_SCAN_STATUS,
    IDC_STATS_HINT,
    IDC_STATS,
    IDC_STATS_CANCEL,
    IDC_COPY,
    IDC_SAVE,
    IDC_STATS_PROGRESS,
    IDC_REPORT,
    IDC_AMST_INFO,
    IDC_AMST_RUN,
    IDC_ABOUT,
    IDC_STATUSBAR,
};

enum class Task { None, Scan, Compare };

constexpr int kPageCount = 4;
constexpr int kProgressMax = 1000;

const wchar_t kAboutText[] =
    L"ADST V3 — 杀毒软件检测数目统计工具\r\n"
    L"版本：" APP_VERSION_STR L"\r\n"
    L"开发者：henry217\r\n"
    L"个人主页：https://home.x64bbs.cn/space-uid-6.html\r\n"
    L"欢迎反馈 bug\r\n"
    L"\r\n"
    L"使用步骤：\r\n"
    L"1. 在【选择文件夹】页选择样本文件夹并扫描，程序会记录每个文件的 MD5。\r\n"
    L"2. 用杀毒软件扫描、处理该文件夹。\r\n"
    L"3. 在【统计】页点击“开始统计”：文件消失计为“删除”，内容变化计为“清除”。";

const wchar_t kAmstText[] = L"该程序用于上报病毒文件";

const wchar_t kStatsHint[] =
    L"先在【选择文件夹】页完成扫描，再让杀毒软件处理该文件夹，然后点击“开始统计”。";

struct App {
    HINSTANCE inst = nullptr;
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    HWND statusBar = nullptr;

    HWND pathLabel = nullptr, path = nullptr, browse = nullptr;
    HWND scanBtn = nullptr, scanCancel = nullptr, scanProgress = nullptr, scanStatus = nullptr;
    HWND statsHint = nullptr, statsBtn = nullptr, statsCancel = nullptr, copyBtn = nullptr, saveBtn = nullptr;
    HWND statsProgress = nullptr, report = nullptr;
    HWND amstInfo = nullptr, amstRun = nullptr;
    HWND about = nullptr;

    std::vector<HWND> pages[kPageCount];
    HFONT font = nullptr;
    HFONT mediumFont = nullptr;
    HFONT largeFont = nullptr;
    UINT dpi = 96;

    // 后台任务
    Task task = Task::None;
    std::thread worker;
    std::atomic<bool> cancel{false};
    std::atomic<int> phase{0};
    std::atomic<std::size_t> done{0};
    std::atomic<std::size_t> total{0};
    std::atomic<bool> progressPending{false};
    ULONGLONG lastProgressPost = 0;  // 仅由后台线程访问

    // 任务结果：后台线程写入后再投递完成消息，UI 线程 join 之后读取
    std::unique_ptr<adst::ScanResult> scanResult;
    std::unique_ptr<adst::Stats> statsResult;

    std::vector<adst::FileRecord> baseline;
    std::wstring baselineRoot;

    bool amstRunning = false;
};

App g;

int S(int v) { return MulDiv(v, static_cast<int>(g.dpi), 96); }

// ---------- 小工具 ----------

std::wstring GetText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(static_cast<std::size_t>(n) + 1, L'\0');
    GetWindowTextW(h, s.data(), n + 1);
    s.resize(static_cast<std::size_t>(n));
    return s;
}

void SetStatus(const std::wstring& text) {
    SendMessageW(g.statusBar, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(text.c_str()));
}

void Warn(const wchar_t* text) { MessageBoxW(g.hwnd, text, L"ADST", MB_OK | MB_ICONWARNING); }

void ShowError(const std::wstring& text) { MessageBoxW(g.hwnd, text.c_str(), L"ADST", MB_OK | MB_ICONERROR); }

std::wstring LastErrorText(DWORD err = GetLastError()) {
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, err, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring s = buf ? buf : L"未知错误";
    if (buf) LocalFree(buf);
    while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r')) s.pop_back();
    return s + L" (" + std::to_wstring(err) + L")";
}

void SetMarquee(HWND bar, bool on) {
    LONG_PTR style = GetWindowLongPtrW(bar, GWL_STYLE);
    bool isOn = (style & PBS_MARQUEE) != 0;
    if (on == isOn) return;
    if (on) {
        SetWindowLongPtrW(bar, GWL_STYLE, style | PBS_MARQUEE);
        SendMessageW(bar, PBM_SETMARQUEE, TRUE, 30);
    } else {
        SendMessageW(bar, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(bar, GWL_STYLE, style & ~static_cast<LONG_PTR>(PBS_MARQUEE));
        SendMessageW(bar, PBM_SETRANGE32, 0, kProgressMax);
    }
}

void SetProgress(HWND bar, std::size_t done, std::size_t total) {
    SetMarquee(bar, false);
    int pos = total ? static_cast<int>(static_cast<double>(done) * kProgressMax / static_cast<double>(total)) : 0;
    SendMessageW(bar, PBM_SETPOS, pos, 0);
}

// ---------- 界面创建与布局 ----------

HWND MakeCtrl(int page, DWORD exStyle, const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
    HWND h = CreateWindowExW(exStyle, cls, text, WS_CHILD | style, 0, 0, 0, 0, g.hwnd,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g.inst, nullptr);
    g.pages[page].push_back(h);
    return h;
}

HWND MakeButton(int page, const wchar_t* text, int id) {
    return MakeCtrl(page, 0, WC_BUTTONW, text, WS_TABSTOP | BS_PUSHBUTTON, id);
}

HFONT MakeFont(int pointSize) {
    return CreateFontW(-MulDiv(pointSize, static_cast<int>(g.dpi), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
}

void ApplyFont() {
    if (g.font) DeleteObject(g.font);
    if (g.largeFont) DeleteObject(g.largeFont);
    if (g.mediumFont) DeleteObject(g.mediumFont);
    g.font = MakeFont(10);
    g.mediumFont = MakeFont(11);  // 统计页的提示和输出
    g.largeFont = MakeFont(12);   // AMST、关于页的说明文字
    EnumChildWindows(
        g.hwnd,
        [](HWND child, LPARAM font) -> BOOL {
            SendMessageW(child, WM_SETFONT, static_cast<WPARAM>(font), TRUE);
            return TRUE;
        },
        reinterpret_cast<LPARAM>(g.font));
    for (HWND h : {g.statsHint, g.report}) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g.mediumFont), TRUE);
    for (HWND h : {g.amstInfo, g.about}) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g.largeFont), TRUE);
}

void ShowPage(int page) {
    for (int i = 0; i < kPageCount; ++i)
        for (HWND h : g.pages[i]) ShowWindow(h, i == page ? SW_SHOW : SW_HIDE);
}

void UpdateButtons() {
    bool idle = g.task == Task::None;
    EnableWindow(g.path, idle);
    EnableWindow(g.browse, idle);
    EnableWindow(g.scanBtn, idle);
    EnableWindow(g.scanCancel, g.task == Task::Scan);
    EnableWindow(g.statsBtn, idle);
    EnableWindow(g.statsCancel, g.task == Task::Compare);
    EnableWindow(g.amstRun, !g.amstRunning);
}

void CreateControls() {
    g.tab = CreateWindowExW(0, WC_TABCONTROLW, nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP, 0, 0,
                            0, 0, g.hwnd, reinterpret_cast<HMENU>(IDC_TAB), g.inst, nullptr);
    const wchar_t* titles[kPageCount] = {L"选择文件夹", L"统计", L"AMST 工具", L"关于"};
    for (int i = 0; i < kPageCount; ++i) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<wchar_t*>(titles[i]);
        SendMessageW(g.tab, TCM_INSERTITEMW, i, reinterpret_cast<LPARAM>(&item));
    }

    // 第 1 页：选择文件夹
    g.pathLabel = MakeCtrl(0, 0, WC_STATICW, L"样本文件夹（也可以把文件夹拖进窗口）：", 0, IDC_PATH_LABEL);
    g.path = MakeCtrl(0, WS_EX_CLIENTEDGE, WC_EDITW, L"", WS_TABSTOP | ES_AUTOHSCROLL, IDC_PATH);
    SendMessageW(g.path, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"选择或拖入一个文件夹"));
    g.browse = MakeButton(0, L"浏览…", IDC_BROWSE);
    g.scanBtn = MakeButton(0, L"开始扫描", IDC_SCAN);
    g.scanCancel = MakeButton(0, L"取消扫描", IDC_SCAN_CANCEL);
    g.scanProgress = MakeCtrl(0, 0, PROGRESS_CLASSW, nullptr, PBS_SMOOTH, IDC_SCAN_PROGRESS);
    g.scanStatus = MakeCtrl(0, 0, WC_STATICW, L"尚未扫描", SS_LEFT | SS_NOPREFIX, IDC_SCAN_STATUS);

    // 第 2 页：统计
    g.statsHint = MakeCtrl(1, 0, WC_STATICW, kStatsHint, SS_LEFT, IDC_STATS_HINT);
    g.statsBtn = MakeButton(1, L"开始统计", IDC_STATS);
    g.statsCancel = MakeButton(1, L"取消统计", IDC_STATS_CANCEL);
    g.copyBtn = MakeButton(1, L"复制结果", IDC_COPY);
    g.saveBtn = MakeButton(1, L"另存为…", IDC_SAVE);
    g.statsProgress = MakeCtrl(1, 0, PROGRESS_CLASSW, nullptr, PBS_SMOOTH, IDC_STATS_PROGRESS);
    g.report = MakeCtrl(1, WS_EX_CLIENTEDGE, WC_EDITW, L"",
                        WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, IDC_REPORT);

    // 第 3 页：AMST
    g.amstInfo = MakeCtrl(2, 0, WC_STATICW, kAmstText, SS_LEFT, IDC_AMST_INFO);
    g.amstRun = MakeButton(2, L"启动 AMST", IDC_AMST_RUN);

    // 第 4 页：关于
    // 用无边框的只读 RichEdit 显示：文字可以选中、复制，网址自动识别为可点击的链接
    g.about = MakeCtrl(3, 0, MSFTEDIT_CLASS, L"", WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, IDC_ABOUT);
    SendMessageW(g.about, EM_SETBKGNDCOLOR, FALSE, static_cast<LPARAM>(GetSysColor(COLOR_WINDOW)));
    SendMessageW(g.about, EM_AUTOURLDETECT, AURL_ENABLEURL, 0);
    SendMessageW(g.about, EM_SETEVENTMASK, 0, ENM_LINK);
    SetWindowTextW(g.about, kAboutText);

    g.statusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0,
                                  g.hwnd, reinterpret_cast<HMENU>(IDC_STATUSBAR), g.inst, nullptr);

    SendMessageW(g.scanProgress, PBM_SETRANGE32, 0, kProgressMax);
    SendMessageW(g.statsProgress, PBM_SETRANGE32, 0, kProgressMax);

    // 让页面控件绘制在 Tab 控件之上
    SetWindowPos(g.tab, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    ApplyFont();
    ShowPage(0);
    UpdateButtons();
    SetStatus(L"就绪");
}

void Place(HWND h, int x, int y, int w, int hgt) { MoveWindow(h, x, y, w, hgt, TRUE); }

void Layout() {
    if (!g.statusBar) return;
    RECT rc;
    GetClientRect(g.hwnd, &rc);
    SendMessageW(g.statusBar, WM_SIZE, 0, 0);
    RECT sb;
    GetWindowRect(g.statusBar, &sb);
    int statusH = sb.bottom - sb.top;

    int m = S(8);
    // Tab 控件只占标签头一条，页面内容画在窗口白色背景上，
    // 避免主题化的 Tab 面板底色与静态文本背景不一致。
    RECT item{};
    SendMessageW(g.tab, TCM_GETITEMRECT, 0, reinterpret_cast<LPARAM>(&item));
    int tabH = item.bottom + S(2);
    Place(g.tab, m, m, rc.right - 2 * m, tabH);

    RECT pr{m, m + tabH, rc.right - m, rc.bottom - statusH};
    int p = S(14);
    int x = pr.left + p;
    int w = (pr.right - pr.left) - 2 * p;
    int bottom = pr.bottom - p;
    int btnH = S(32), btnW = S(110), gap = S(10);

    // 第 1 页
    int y = pr.top + p;
    Place(g.pathLabel, x, y, w, S(22));
    y += S(26);
    int browseW = S(90);
    Place(g.path, x, y, w - browseW - gap, S(30));
    Place(g.browse, x + w - browseW, y, browseW, S(30));
    y += S(30) + S(16);
    Place(g.scanBtn, x, y, btnW, btnH);
    Place(g.scanCancel, x + btnW + gap, y, btnW, btnH);
    y += btnH + S(20);
    Place(g.scanProgress, x, y, w, S(22));
    y += S(22) + S(10);
    Place(g.scanStatus, x, y, w, std::max<int>(S(24), bottom - y));

    // 第 2 页
    y = pr.top + p;
    Place(g.statsHint, x, y, w, S(48));
    y += S(52);
    Place(g.statsBtn, x, y, btnW, btnH);
    Place(g.statsCancel, x + (btnW + gap), y, btnW, btnH);
    Place(g.copyBtn, x + 2 * (btnW + gap), y, btnW, btnH);
    Place(g.saveBtn, x + 3 * (btnW + gap), y, btnW, btnH);
    y += btnH + S(12);
    Place(g.statsProgress, x, y, w, S(16));
    y += S(16) + S(10);
    Place(g.report, x, y, w, std::max<int>(S(60), bottom - y));

    // 第 3 页
    y = pr.top + p;
    Place(g.amstInfo, x, y, w, S(30));
    y += S(44);
    Place(g.amstRun, x, y, S(140), btnH);

    // 第 4 页
    Place(g.about, x, pr.top + p, w, std::max<int>(S(60), bottom - pr.top - p));
}

// ---------- 后台任务 ----------

void OnWorkerProgress(adst::Phase phase, std::size_t done, std::size_t total) {
    g.phase.store(static_cast<int>(phase), std::memory_order_relaxed);
    g.done.store(done, std::memory_order_relaxed);
    g.total.store(total, std::memory_order_relaxed);
    ULONGLONG now = GetTickCount64();
    if (now - g.lastProgressPost < 50) return;  // 节流：最多每 50ms 刷新一次界面
    g.lastProgressPost = now;
    if (!g.progressPending.exchange(true)) PostMessageW(g.hwnd, WM_APP_PROGRESS, 0, 0);
}

template <typename Fn>
void StartTask(Task task, Fn&& body) {
    g.task = task;
    g.cancel = false;
    g.progressPending = false;
    g.lastProgressPost = 0;
    UpdateButtons();
    g.worker = std::thread(std::forward<Fn>(body));
}

void FinishTask() {
    if (g.worker.joinable()) g.worker.join();
    g.task = Task::None;
    UpdateButtons();
}

void StartScan() {
    std::wstring root = GetText(g.path);
    if (!adst::IsDirectory(root)) {
        Warn(L"路径不存在或不是文件夹。");
        return;
    }
    root = adst::FullPath(root);
    SetWindowTextW(g.path, root.c_str());
    g.baseline.clear();
    g.baselineRoot.clear();
    SetWindowTextW(g.report, L"");
    SetMarquee(g.scanProgress, true);
    SetWindowTextW(g.scanStatus, L"正在枚举文件…");
    SetStatus(L"正在扫描：" + root);

    StartTask(Task::Scan, [root] {
        auto res = std::make_unique<adst::ScanResult>(adst::Scan(root, g.cancel, OnWorkerProgress));
        g.scanResult = std::move(res);
        PostMessageW(g.hwnd, WM_APP_SCAN_DONE, 0, 0);
    });
    g.baselineRoot = root;
}

void OnScanDone() {
    FinishTask();
    std::unique_ptr<adst::ScanResult> res = std::move(g.scanResult);
    if (!res || res->cancelled) {
        g.baseline.clear();
        g.baselineRoot.clear();
        SetProgress(g.scanProgress, 0, 1);
        SetWindowTextW(g.scanStatus, L"扫描已取消");
        SetStatus(L"扫描已取消");
        return;
    }
    g.baseline = std::move(res->files);
    SetProgress(g.scanProgress, 1, 1);

    std::wstring msg = L"扫描完毕，共记录 " + std::to_wstring(g.baseline.size()) + L" 个文件。";
    if (res->unreadable) msg += L"\r\n有 " + std::to_wstring(res->unreadable) + L" 个文件无法读取，已跳过。";
    if (res->dirErrors) msg += L"\r\n有 " + std::to_wstring(res->dirErrors) + L" 个目录无法访问，已跳过。";
    msg += L"\r\n现在可以用杀毒软件处理该文件夹，完成后到【统计】页查看结果。";
    SetWindowTextW(g.scanStatus, msg.c_str());
    SetStatus(L"扫描完毕：" + std::to_wstring(g.baseline.size()) + L" 个文件");
}

void StartCompare() {
    if (g.baseline.empty()) {
        Warn(L"还没有扫描结果，请先在【选择文件夹】页扫描。");
        return;
    }
    SetProgress(g.statsProgress, 0, 1);
    SetStatus(L"正在统计…");
    // baseline 在任务期间只读：扫描按钮在任务期间被禁用，不会被修改
    StartTask(Task::Compare, [] {
        auto st = std::make_unique<adst::Stats>(adst::Compare(g.baseline, g.cancel, OnWorkerProgress));
        g.statsResult = std::move(st);
        PostMessageW(g.hwnd, WM_APP_STATS_DONE, 0, 0);
    });
}

void OnStatsDone() {
    FinishTask();
    std::unique_ptr<adst::Stats> st = std::move(g.statsResult);
    if (!st || st->cancelled) {
        SetProgress(g.statsProgress, 0, 1);
        SetStatus(L"统计已取消");
        return;
    }
    SetProgress(g.statsProgress, 1, 1);
    std::wstring text = L"样本文件夹: " + g.baselineRoot + L"\r\n" + adst::FormatReport(*st, APP_VERSION_STR);
    SetWindowTextW(g.report, text.c_str());
    SetStatus(L"统计完成");
}

void OnProgress() {
    g.progressPending = false;
    auto phase = static_cast<adst::Phase>(g.phase.load());
    std::size_t done = g.done.load(), total = g.total.load();
    switch (phase) {
        case adst::Phase::Counting:
            SetMarquee(g.scanProgress, true);
            SetWindowTextW(g.scanStatus, (L"正在枚举文件… 已发现 " + std::to_wstring(done) + L" 个").c_str());
            break;
        case adst::Phase::Hashing:
            SetProgress(g.scanProgress, done, total);
            SetWindowTextW(g.scanStatus,
                           (L"正在计算 MD5… " + std::to_wstring(done) + L" / " + std::to_wstring(total)).c_str());
            break;
        case adst::Phase::Comparing:
            SetProgress(g.statsProgress, done, total);
            SetStatus(L"正在统计… " + std::to_wstring(done) + L" / " + std::to_wstring(total));
            break;
    }
}

void CancelTask() {
    if (g.task == Task::None) return;
    g.cancel = true;
    SetStatus(L"正在取消…");
}

// ---------- 其他功能 ----------

void BrowseFolder() {
    IFileOpenDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) return;
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dlg->SetTitle(L"选择样本文件夹");

    std::wstring current = GetText(g.path);
    if (adst::IsDirectory(current)) {
        IShellItem* folder = nullptr;
        if (SUCCEEDED(SHCreateItemFromParsingName(adst::FullPath(current).c_str(), nullptr, IID_PPV_ARGS(&folder)))) {
            dlg->SetFolder(folder);
            folder->Release();
        }
    }

    if (SUCCEEDED(dlg->Show(g.hwnd))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item))) {
            PWSTR p = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &p))) {
                SetWindowTextW(g.path, p);
                CoTaskMemFree(p);
            }
            item->Release();
        }
    }
    dlg->Release();
}

void OnDropFiles(HDROP drop) {
    UINT len = DragQueryFileW(drop, 0, nullptr, 0);
    std::wstring file(len + 1, L'\0');
    DragQueryFileW(drop, 0, file.data(), len + 1);
    file.resize(len);
    DragFinish(drop);

    if (g.task != Task::None) {
        SetStatus(L"任务进行中，暂时不能更换文件夹");
        return;
    }
    if (!adst::IsDirectory(file)) {
        Warn(L"只接受文件夹。");
        return;
    }
    SetWindowTextW(g.path, file.c_str());
    SendMessageW(g.tab, TCM_SETCURSEL, 0, 0);
    ShowPage(0);
}

void CopyReport() {
    std::wstring text = GetText(g.report);
    if (text.empty()) {
        Warn(L"还没有统计结果。");
        return;
    }
    if (!OpenClipboard(g.hwnd)) {
        ShowError(L"无法打开剪贴板：" + LastErrorText());
        return;
    }
    EmptyClipboard();
    std::size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    bool ok = false;
    if (mem) {
        if (void* dst = GlobalLock(mem)) {
            memcpy(dst, text.c_str(), bytes);
            GlobalUnlock(mem);
            ok = SetClipboardData(CF_UNICODETEXT, mem) != nullptr;
        }
        if (!ok) GlobalFree(mem);
    }
    CloseClipboard();
    SetStatus(ok ? L"已复制到剪贴板" : L"复制失败");
}

void SaveReport() {
    std::wstring text = GetText(g.report);
    if (text.empty()) {
        Warn(L"还没有统计结果。");
        return;
    }
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t name[MAX_PATH];
    swprintf(name, MAX_PATH, L"ADST统计_%04u%02u%02u_%02u%02u%02u.txt", t.wYear, t.wMonth, t.wDay, t.wHour,
             t.wMinute, t.wSecond);

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.hwnd;
    ofn.lpstrFilter = L"文本文件 (*.txt)\0*.txt\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrFile = name;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return;

    int n = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8 = "\xEF\xBB\xBF";  // BOM，记事本等能正确识别编码
    std::size_t off = utf8.size();
    utf8.resize(off + static_cast<std::size_t>(n));
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), utf8.data() + off, n, nullptr,
                        nullptr);

    HANDLE f = CreateFileW(name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        ShowError(L"无法创建文件：" + LastErrorText());
        return;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    DWORD err = GetLastError();
    CloseHandle(f);
    if (!ok || written != utf8.size()) {
        ShowError(L"写入文件失败：" + LastErrorText(err));
        return;
    }
    SetStatus(std::wstring(L"已保存到 ") + name);
}

void LaunchAmst() {
    if (g.amstRunning) return;

    HRSRC res = FindResourceW(g.inst, MAKEINTRESOURCEW(IDR_AMST), RT_RCDATA);
    HGLOBAL data = res ? LoadResource(g.inst, res) : nullptr;
    const void* bytes = data ? LockResource(data) : nullptr;
    DWORD size = res ? SizeofResource(g.inst, res) : 0;
    if (!bytes || !size) {
        ShowError(L"找不到内嵌的 AMST 资源。");
        return;
    }

    // 放到独立的临时子目录，避免与其他实例冲突
    wchar_t tmp[MAX_PATH + 1];
    DWORD tmpLen = GetTempPathW(MAX_PATH + 1, tmp);
    if (!tmpLen) {
        ShowError(L"无法获取临时目录：" + LastErrorText());
        return;
    }
    std::wstring dir = std::wstring(tmp) + L"ADST_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                       std::to_wstring(GetTickCount64());
    if (!CreateDirectoryW(dir.c_str(), nullptr)) {
        ShowError(L"无法创建临时目录：" + LastErrorText());
        return;
    }
    std::wstring exe = dir + L"\\AMST.exe";

    HANDLE f = CreateFileW(exe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        ShowError(L"无法释放 AMST：" + LastErrorText());
        RemoveDirectoryW(dir.c_str());
        return;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(f, bytes, size, &written, nullptr) && written == size;
    CloseHandle(f);
    if (!ok) {
        ShowError(L"无法释放 AMST：" + LastErrorText());
        DeleteFileW(exe.c_str());
        RemoveDirectoryW(dir.c_str());
        return;
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = g.hwnd;
    sei.lpVerb = L"open";
    sei.lpFile = exe.c_str();
    sei.lpDirectory = dir.c_str();
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
        ShowError(L"启动 AMST 失败：" + LastErrorText());
        DeleteFileW(exe.c_str());
        RemoveDirectoryW(dir.c_str());
        return;
    }

    g.amstRunning = true;
    UpdateButtons();
    SetStatus(L"AMST 已启动");

    // 在后台等待 AMST 退出并清理，不阻塞界面
    HANDLE proc = sei.hProcess;
    HWND hwnd = g.hwnd;
    std::thread([proc, exe, dir, hwnd] {
        if (proc) {
            WaitForSingleObject(proc, INFINITE);
            CloseHandle(proc);
        }
        for (int i = 0; i < 25 && !DeleteFileW(exe.c_str()); ++i) Sleep(200);
        RemoveDirectoryW(dir.c_str());
        PostMessageW(hwnd, WM_APP_AMST_DONE, 0, 0);
    }).detach();
}

// 关于页中点击链接：用默认浏览器打开（只处理 http/https）
void OnAboutLink(const ENLINK& link) {
    if (link.msg != WM_LBUTTONUP) return;
    LONG len = link.chrg.cpMax - link.chrg.cpMin;
    if (len <= 0 || len > 2048) return;
    std::wstring url(static_cast<std::size_t>(len) + 1, L'\0');
    TEXTRANGEW tr{};
    tr.chrg = link.chrg;
    tr.lpstrText = url.data();
    SendMessageW(g.about, EM_GETTEXTRANGE, 0, reinterpret_cast<LPARAM>(&tr));
    url.resize(wcslen(url.c_str()));
    if (url.rfind(L"https://", 0) != 0 && url.rfind(L"http://", 0) != 0) return;
    ShellExecuteW(g.hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

// ---------- 窗口过程 ----------

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            g.hwnd = hwnd;
            g.dpi = GetDpiForWindow(hwnd);
            CreateControls();
            DragAcceptFiles(hwnd, TRUE);
            return 0;

        case WM_SIZE:
            Layout();
            return 0;

        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize = {S(640), S(440)};
            return 0;
        }

        case WM_DPICHANGED: {
            g.dpi = HIWORD(wp);
            ApplyFont();
            const RECT* r = reinterpret_cast<const RECT*>(lp);
            SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            Layout();
            return 0;
        }

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
            SetBkColor(dc, GetSysColor(COLOR_WINDOW));
            return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
        }

        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<NMHDR*>(lp);
            if (nm->hwndFrom == g.tab && nm->code == TCN_SELCHANGE)
                ShowPage(static_cast<int>(SendMessageW(g.tab, TCM_GETCURSEL, 0, 0)));
            else if (nm->hwndFrom == g.about && nm->code == EN_LINK)
                OnAboutLink(*reinterpret_cast<ENLINK*>(lp));
            return 0;
        }

        case WM_COMMAND:
            if (HIWORD(wp) == BN_CLICKED) {
                switch (LOWORD(wp)) {
                    case IDC_BROWSE: BrowseFolder(); break;
                    case IDC_SCAN: StartScan(); break;
                    case IDC_SCAN_CANCEL:
                    case IDC_STATS_CANCEL: CancelTask(); break;
                    case IDC_STATS: StartCompare(); break;
                    case IDC_COPY: CopyReport(); break;
                    case IDC_SAVE: SaveReport(); break;
                    case IDC_AMST_RUN: LaunchAmst(); break;
                }
            }
            return 0;

        case WM_DROPFILES:
            OnDropFiles(reinterpret_cast<HDROP>(wp));
            return 0;

        case WM_APP_PROGRESS: OnProgress(); return 0;
        case WM_APP_SCAN_DONE: OnScanDone(); return 0;
        case WM_APP_STATS_DONE: OnStatsDone(); return 0;
        case WM_APP_AMST_DONE:
            g.amstRunning = false;
            UpdateButtons();
            SetStatus(L"AMST 已退出，临时文件已清理");
            return 0;

        case WM_DESTROY:
            if (g.worker.joinable()) {
                g.cancel = true;
                g.worker.join();
            }
            if (g.font) DeleteObject(g.font);
            if (g.largeFont) DeleteObject(g.largeFont);
            if (g.mediumFont) DeleteObject(g.mediumFont);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
    g.inst = inst;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES |
                                              ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    LoadLibraryW(L"Msftedit.dll");  // 注册 RichEdit 控件类（关于页使用）

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hIcon = static_cast<HICON>(LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXICON),
                                             GetSystemMetrics(SM_CYICON), 0));
    wc.hIconSm = static_cast<HICON>(LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
                                               GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ADST_MainWindow";
    RegisterClassExW(&wc);

    UINT dpi = GetDpiForSystem();
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"ADST V3 — 杀毒软件检测数目统计工具", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, MulDiv(800, dpi, 96), MulDiv(560, dpi, 96), nullptr,
                                nullptr, inst, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (IsDialogMessageW(hwnd, &msg)) continue;  // 支持 Tab 键在控件间切换
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
