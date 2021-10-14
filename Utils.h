#pragma once

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <initializer_list>
#include <vector>

namespace Utils {
    std::vector<char> HexToBytes(const std::string& hex);
    std::string BytesToString(unsigned char* data, int len);
    std::vector<std::string> Split(const std::string& str, const char* delim);

    /*
     * @brief Create console
     *
     * Create and attach a console window to the current process
     */
    void AttachConsole();

    /*
     * @brief Detach console
     *
     * Detach and destroy the attached console
     */
    void DetachConsole();

    /*
     * @brief Print to console
     *
     * Replacement to printf that works with the newly created console
     */
    bool ConsolePrint(const char* fmt, ...);

    /*
     * @brief Blocks execution until a key is pressed on the console window
     *
     */
    char ConsoleReadKey();


}
