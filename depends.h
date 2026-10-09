#pragma once
#include "context.h"
#include <string>
#include <vector>

namespace depends {
    std::string PathToSave(const char* addDirectory) {
        std::vector<char> buffer(MAX_PATH);
        for (;;) {
            const DWORD length = GetCurrentDirectoryA(static_cast<DWORD>(buffer.size()), buffer.data());
            if (length == 0)
                return addDirectory;
            if (length < buffer.size())
                return std::string(buffer.data(), length) + addDirectory;
            buffer.resize(length);
        }
    }
}