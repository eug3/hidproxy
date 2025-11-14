cmake_minimum_required(VERSION 3.15)
project(HidLauncher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Launcher executable (starts process with DLL injection)
add_executable(hid_launcher
    launcher/main.cpp
    launcher/app.manifest
)

# HID Hook DLL (injected DLL)
add_library(hid_hook SHARED
    hook_dll/dllmain.cpp
    hook_dll/hid_hooks.cpp
    hook_dll/network_hooks.cpp
    hook_dll/logging.cpp
)

# Configure launcher with admin manifest
set_target_properties(hid_launcher PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /MANIFEST:EMBED"
)

target_compile_definitions(hid_hook PRIVATE
    UNICODE
    _UNICODE
)

target_link_libraries(hid_hook PRIVATE
    hid.lib
    setupapi.lib
    ws2_32.lib
    advapi32.lib
)

# If Detours library exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/detours/detours.lib")
    target_include_directories(hid_hook PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/detours
    )
    target_link_libraries(hid_hook PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/detours/detours.lib
    )
    target_compile_definitions(hid_hook PRIVATE USE_DETOURS)
    message(STATUS "Detours library found - Full Hook mode enabled")
else()
    message(STATUS "Detours library not found - Basic monitoring mode")
endif()

# Set output directory
set_target_properties(hid_launcher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(hid_hook PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install targets
install(TARGETS hid_launcher hid_hook
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION bin
)
