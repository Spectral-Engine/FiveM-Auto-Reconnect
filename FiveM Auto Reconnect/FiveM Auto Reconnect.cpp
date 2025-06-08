#define CURL_STATICLIB
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <shellapi.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <string>
#include <set>
#include <cstdio>
#include <map>
#include "json.hpp"
#include "curl/curl.h"
#pragma comment(lib, "curl/libcurl_a.lib")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")

using json = nlohmann::json;

bool joining = false;
std::thread animation_thread;
std::atomic<bool> animation_running(false);
std::mutex animation_mutex;
std::condition_variable animation_var;
std::wstring animation_base_message;

struct Config
{
    std::string server_url{};
    std::string webhook_url{};
    std::string target_ip{};
    std::string target_port{};
    int start_hour{ 0 };
    int start_minute{ 0 };
    int end_hour{ 0 };
    int end_minute{ 0 };
} config;

enum class LogColor
{
    DEFAULT,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    CYAN,
    MAGENTA,
    WHITE
};
LogColor animation_color = LogColor::DEFAULT;

void SetConsoleColor(LogColor color)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    switch (color)
    {
    case LogColor::RED:     SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_INTENSITY); break;
    case LogColor::GREEN:   SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
    case LogColor::YELLOW:  SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
    case LogColor::BLUE:    SetConsoleTextAttribute(console, FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
    case LogColor::CYAN:    SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
    case LogColor::MAGENTA: SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
    case LogColor::WHITE:   SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    default:                SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    }
}

void SendDiscordMessage(const std::string& message)
{
    const std::string webhook_url = config.webhook_url;
    std::string json_payload = R"({"content":")" + message + R"("})";
    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();

    if (curl)
    {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, webhook_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            //error
        }
        else
        {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

void AnimationLoop()
{
    int index = 0;
    std::unique_lock<std::mutex> lock(animation_mutex);
    const std::wstring dots[] = { L".   ", L"..  ", L"... ", L".   ", L"..  ", L"... " };

    while (animation_running.load())
    {
        SetConsoleColor(animation_color);
        std::wcout << L"\r" << animation_base_message << dots[index] << L"   ";
        std::wcout.flush();
        lock.unlock();
        {
            std::unique_lock<std::mutex> cvLock(animation_mutex);
            if (animation_var.wait_for(cvLock, std::chrono::milliseconds(500), [] { return !animation_running.load(); }))
                break;
        }
        lock.lock();
        index = (index + 1) % 6;
    }
    SetConsoleColor(animation_color);
    std::wcout << L"\r" << animation_base_message << L"...   " << std::endl;
    SetConsoleColor(LogColor::DEFAULT);
}

void StartAnimation(const std::wstring& baseMessage, LogColor color)
{
    if (animation_running.load())
    {
        animation_running.store(false);
        animation_var.notify_all();
        if (animation_thread.joinable())
            animation_thread.join();
    }
    animation_base_message = baseMessage;
    animation_color = color;
    animation_running.store(true);
    animation_thread = std::thread(AnimationLoop);
}

void StopAnimation()
{
    if (animation_running.load())
    {
        animation_running.store(false);
        animation_var.notify_all();
        if (animation_thread.joinable())
            animation_thread.join();
    }
}

void LogMessage(const std::wstring& message, LogColor color = LogColor::DEFAULT, const std::wstring& log_file = L"log.txt")
{
    StopAnimation();

    auto now = std::chrono::system_clock::now();
    std::time_t time_now = std::chrono::system_clock::to_time_t(now);
    std::tm local_time;
    localtime_s(&local_time, &time_now);

    std::wstringstream timestamp_message;
    timestamp_message << L"[" << std::put_time(&local_time, L"%Y-%m-%d %H:%M:%S") << L"] " << message;
    std::wofstream log(log_file, std::ios::app);

    //if (discord_log) SendDiscordMessage(std::string(message.begin(), message.end()));

    if (log.is_open())
    {
        log << timestamp_message.str() << std::endl;
        log.close();
    }
    if (message.size() >= 3 && message.compare(message.size() - 3, 3, L"...") == 0)
    {
        std::wstringstream ss;
        ss << L"[" << std::put_time(&local_time, L"%Y-%m-%d %H:%M:%S") << L"] " << message.substr(0, message.size() - 3);
        std::wstring base_message = ss.str();
        StartAnimation(base_message, color);
    }
    else
    {
        SetConsoleColor(color);
        std::wcout << timestamp_message.str() << std::endl;
        SetConsoleColor(LogColor::DEFAULT);
    }
}
bool LoadConfig(const std::string& path = "config.json")
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        LogMessage(L"[Warning] config.json not found. Creating default config...", LogColor::YELLOW);

        json default_config =
        {
            {"server_url", "fivem://connect/127.0.0.1"},
            {"webhook_url", "https://discord.com/api/webhooks/..."},
            {"target_ip", "127.0.0.1"},
            {"target_port", "30120"},
            {"start_hour", 0},
            {"start_minute", 0},
            {"end_hour", 23},
            {"end_minute", 59}
        };

        std::ofstream new_file(path);
        if (!new_file.is_open())
        {
            LogMessage(L"[Error] Failed to create config.json", LogColor::RED);
            return false;
        }

        new_file << default_config.dump(4);
        new_file.close();
        LogMessage(L"[Info] Default config.json created.", LogColor::WHITE);
        return true;
    }

    try
    {
        json j;
        file >> j;
        config.server_url = j["server_url"];
        config.webhook_url = j["webhook_url"];
        config.target_ip = j["target_ip"];
        config.target_port = j["target_port"];
        config.start_hour = j["start_hour"];
        config.start_minute = j["start_minute"];
        config.end_hour = j["end_hour"];
        config.end_minute = j["end_minute"];
    }
    catch (std::exception& e)
    {
        LogMessage(L"[Error] Failed to parse config.json", LogColor::RED);
        return false;
    }
    return true;
}

void DisableQuickEdit()
{
    HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE)
    {
        LogMessage(L"[Error] GetStdHandle", LogColor::RED);
        return;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(handle, &mode))
    {
        LogMessage(L"[Error] GetConsoleMode", LogColor::RED);
        return;
    }
    mode &= ~ENABLE_QUICK_EDIT_MODE;
    mode |= ENABLE_EXTENDED_FLAGS;

    if (!SetConsoleMode(handle, mode))
    {
        LogMessage(L"[Error] SetConsoleMode", LogColor::RED);
    }
}

void PrintAsciiArt()
{
    SetConsoleColor(LogColor::CYAN);
    std::wcout << LR"(
  ______ _           __  __                 _          _____                                      _   
 |  ____(_)         |  \/  |     /\        | |        |  __ \                                    | |  
 | |__   ___   _____| \  / |    /  \  _   _| |_ ___   | |__) |___  ___ ___  _ __  _ __   ___  ___| |_ 
 |  __| | \ \ / / _ \ |\/| |   / /\ \| | | | __/ _ \  |  _  // _ \/ __/ _ \| '_ \| '_ \ / _ \/ __| __|
 | |    | |\ V /  __/ |  | |  / ____ \ |_| | || (_) | | | \ \  __/ (_| (_) | | | | | | |  __/ (__| |_ 
 |_|    |_| \_/ \___|_|  |_| /_/    \_\__,_|\__\___/  |_|  \_\___|\___\___/|_| |_|_| |_|\___|\___|\__|
                                                                                                      
                                                                                                                                                                                           
)" << std::endl;
    SetConsoleColor(LogColor::DEFAULT);
}

void SetupConsole()
{
    SetConsoleTitleW(L"FiveM Auto Reconnect");
    DisableQuickEdit();
    HWND console = GetConsoleWindow();
    SetLayeredWindowAttributes(console, 0, 220, LWA_ALPHA);
    PrintAsciiArt();
}

bool IsFiveMRunning()
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, L"FiveM_GTAProcess.exe") == 0)
            {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return false;
}

void KillFiveM()
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, L"FiveM_GTAProcess.exe") == 0)
            {
                HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (process)
                {
                    TerminateProcess(process, 0);
                    CloseHandle(process);
                    LogMessage(L"[Info] FiveM has been terminated.", LogColor::WHITE);
                }
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void JoinServer()
{
    joining = true;
    ShellExecuteW(NULL, L"open", L"explorer.exe", std::wstring(config.server_url.begin(), config.server_url.end()).c_str(), NULL, SW_SHOWNORMAL);
    LogMessage(L"[Info] Joining server...", LogColor::WHITE);
    SendDiscordMessage("**[Info]** Joining server...");
}

bool ShouldBeConnected()
{
    SYSTEMTIME time;
    GetLocalTime(&time);
    int hour = time.wHour;
    int minute = time.wMinute;
    int current_minutes = hour * 60 + minute;
    int start = config.start_hour * 60 + config.start_minute;
    int end = config.end_hour * 60 + config.end_minute;

    return (current_minutes >= start || current_minutes < end);
}

bool IsConnected()
{
    static ULONGLONG last_check_time = GetTickCount64();
    const ULONGLONG timeout_ms = 10 * 60 * 1000;

    FILE* netstat = _popen("netstat -n", "r");
    if (!netstat)
    {
        LogMessage(L"[Error] Failed to execute netstat.", LogColor::RED);
        if (joining) joining = false;
        return false;
    }
    const std::string target = config.target_ip + ":" + config.target_port;
    char buffer[512];
    bool target_seen = false;

    while (fgets(buffer, sizeof(buffer), netstat))
    {
        std::string line(buffer);
        std::istringstream iss(line);
        std::string proto, local_address, remote_address, state;
        iss >> proto >> local_address >> remote_address >> state;
        if (proto != "TCP" || local_address.empty() || remote_address.empty() || state.empty())
            continue;

        if (remote_address == target)
        {
            if (state == "ESTABLISHED")
            {
                last_check_time = GetTickCount64();
                _pclose(netstat);
                return true;
            }
        }
    }

    ULONGLONG now = GetTickCount64();
    if (now - last_check_time >= timeout_ms)
    {
        if (joining)
        {
            LogMessage(L"[Warning] Connection attempt timed out (no ESTABLISHED state for 10 minutes).", LogColor::YELLOW);
            SendDiscordMessage("**[Warning]** Connection attempt timed out (no ESTABLISHED state for 10 minutes).");
            joining = false;
        }
        last_check_time = now;
        _pclose(netstat);
        return false;
    }

    _pclose(netstat);
    return true;
}


int main()
{
    SetupConsole();
    if (!LoadConfig()) return 1;
    LogMessage(L"[Info] Waiting for the server to restart...", LogColor::CYAN);
    while (true)
    {
        const bool is_connected = IsConnected();
        const bool is_fivem_running = IsFiveMRunning();
        const bool should_be_connected = ShouldBeConnected();

        if (!should_be_connected && is_fivem_running)
        {
            KillFiveM();
            std::this_thread::sleep_for(std::chrono::seconds(20));
        }

        if (!is_connected && should_be_connected)
        {
            if (!joining)
            {
                LogMessage(L"[Warning] You're not connected to the server.", LogColor::YELLOW);
                SendDiscordMessage("**[Warning]** You're not connected to the server.");
                if (is_fivem_running)
                {
                    KillFiveM();
                    std::this_thread::sleep_for(std::chrono::seconds(20));
                }
                JoinServer();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return 0;
}


