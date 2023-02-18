#pragma once
#include <Windows.h>

namespace fusion::anti_debug
{
    _Use_decl_annotations_
        BOOL
        RmpRemapImage(
            ULONG_PTR ImageBase
        );

}