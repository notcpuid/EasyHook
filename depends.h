#pragma once
#include "context.h"

namespace depends {
    char* PathToSave(char* addDirectory) {
        char buffer[256];
        GetCurrentDirectoryA(sizeof(buffer), buffer);
        char dest[512];
        strcpy(dest, buffer);
        strcat(dest, addDirectory);

        return _strdup(dest);
    }
}