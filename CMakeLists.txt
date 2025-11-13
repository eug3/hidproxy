cmake_minimum_required(VERSION 3.15)
project(hidproxy VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出目录 - DLL 和 EXE 都放在 bin 目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================
# HID Proxy DLL (使用 LoadLibrary 动态转发)
# ============================================
add_library(hid SHARED
    src/dllmain.cpp
    src/hid_wrappers_simple.cpp
    src/hid_proxy.h
    src/hid.def
)

# 包含目录
target_include_directories(hid PRIVATE src)

# 不链接任何系统库 - 转发在 .def 文件中定义

# 设置编译选项
if(MSVC)
    target_compile_options(hid PRIVATE /W4 /utf-8)
    target_compile_definitions(hid PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(hid PRIVATE -Wall -Wextra)
endif()

# ============================================
# HID Device Enumeration Console
# ============================================
add_executable(hid_console
    console/main.cpp
)

# 链接必要的系统库
target_link_libraries(hid_console PRIVATE 
    hid.lib
    setupapi.lib
)

# 设置编译选项
if(MSVC)
    target_compile_options(hid_console PRIVATE /W4 /utf-8)
    target_compile_definitions(hid_console PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(hid_console PRIVATE -Wall -Wextra)
endif()

# 添加依赖关系：确保控制台程序在 DLL 之后编译
add_dependencies(hid_console hid)

# 自动复制 DLL 到控制台程序目录（构建后事件）
add_custom_command(TARGET hid_console POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:hid>
        $<TARGET_FILE_DIR:hid_console>
    COMMENT "Copying hid.dll to console output directory"
)

# 安装规则
install(TARGETS hid hid_console
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION bin
)
