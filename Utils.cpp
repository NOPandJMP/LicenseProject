#include "Utils.h"

#define NOMINMAX
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>




HANDLE _out = NULL, _old_out = NULL;
HANDLE _err = NULL, _old_err = NULL;
HANDLE _in = NULL, _old_in = NULL;

namespace Utils {
    std::vector<char> HexToBytes(const std::string& hex) {
        std::vector<char> res;

        for (auto i = 0u; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char byte = (char)strtol(byteString.c_str(), NULL, 16);
            res.push_back(byte);
        }

        return res;
    }
    std::string BytesToString(unsigned char* data, int len) {
        constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        std::string res(len * 2, ' ');
        for (int i = 0; i < len; ++i) {
            res[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
            res[2 * i + 1] = hexmap[data[i] & 0x0F];
        }
        return res;
    }
    std::vector<std::string> Split(const std::string& str, const char* delim) {
        std::vector<std::string> res;
        char* pTempStr = _strdup(str.c_str());
        char* context = NULL;
        char* pWord = strtok_s(pTempStr, delim, &context);
        while (pWord != NULL) {
            res.push_back(pWord);
            pWord = strtok_s(NULL, delim, &context);
        }

        free(pTempStr);

        return res;
    }


    /*
     * @brief Create console
     *
     * Create and attach a console window to the current process
     */
    void AttachConsole()
    {
        _old_out = GetStdHandle(STD_OUTPUT_HANDLE);
        _old_err = GetStdHandle(STD_ERROR_HANDLE);
        _old_in = GetStdHandle(STD_INPUT_HANDLE);

        ::AllocConsole() && ::AttachConsole(GetCurrentProcessId());

        _out = GetStdHandle(STD_OUTPUT_HANDLE);
        _err = GetStdHandle(STD_ERROR_HANDLE);
        _in = GetStdHandle(STD_INPUT_HANDLE);

        SetConsoleMode(_out,
            ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

        SetConsoleMode(_in,
            ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
            ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);
    }

    /*
     * @brief Detach console
     *
     * Detach and destroy the attached console
     */
    void DetachConsole()
    {
        if (_out && _err && _in) {
            FreeConsole();

            if (_old_out)
                SetStdHandle(STD_OUTPUT_HANDLE, _old_out);
            if (_old_err)
                SetStdHandle(STD_ERROR_HANDLE, _old_err);
            if (_old_in)
                SetStdHandle(STD_INPUT_HANDLE, _old_in);
        }
    }

    /*
     * @brief Print to console
     *
     * Replacement to printf that works with the newly created console
     */
    bool ConsolePrint(const char* fmt, ...)
    {
        if (!_out)
            return false;

        char buf[1024];
        va_list va;

        va_start(va, fmt);
        _vsnprintf_s(buf, 1024, fmt, va);
        va_end(va);

        return !!WriteConsoleA(_out, buf, static_cast<DWORD>(strlen(buf)), nullptr, nullptr);
    }

    /*
     * @brief Blocks execution until a key is pressed on the console window
     *
     */
    char ConsoleReadKey()
    {
        if (!_in)
            return false;

        auto key = char{ 0 };
        auto keysread = DWORD{ 0 };

        ReadConsoleA(_in, &key, 1, &keysread, nullptr);

        return key;
    }





}