cmake_minimum_required(VERSION 3.15)
project(HidLauncher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use static runtime library to avoid dependency on MSVCP140.dll and VCRUNTIME140.dll
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
# Alternative: set compiler flags directly
if(MSVC)
    # Replace /MD with /MT (static runtime)
    foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE 
                     CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
                     CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE 
                     CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
endif()

# Launcher executable (starts process with DLL injection)
# Changed to console application for better debugging output
add_executable(Xsjzb_launcher
    launcher/main.cpp
    launcher/app.manifest
    launcher/app.rc
)

# HID Hook DLL (injected DLL)
add_library(Xsjzb_hook SHARED
    hook_dll/dllmain.cpp
    hook_dll/hid_hooks.cpp
    hook_dll/network_hooks.cpp
    hook_dll/logging.cpp
)

# Configure launcher with admin manifest
set_target_properties(Xsjzb_launcher PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /MANIFEST:EMBED"
)

target_compile_definitions(Xsjzb_hook PRIVATE
    UNICODE
    _UNICODE
)

target_link_libraries(Xsjzb_hook PRIVATE
    hid.lib
    setupapi.lib
    ws2_32.lib
    advapi32.lib
)

# Determine platform-specific Detours library path
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DETOURS_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/detours_src/lib.X64/detours.lib")
    set(DETOURS_ARCH "x64")
else()
    set(DETOURS_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/detours_src/lib.X86/detours.lib")
    set(DETOURS_ARCH "x86")
endif()

# If Detours library exists
if(EXISTS "${DETOURS_LIB_PATH}")
    target_include_directories(Xsjzb_hook PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/detours_src/include
    )
    target_link_libraries(Xsjzb_hook PRIVATE
        ${DETOURS_LIB_PATH}
    )
    target_compile_definitions(Xsjzb_hook PRIVATE USE_DETOURS)
    message(STATUS "Detours library found (${DETOURS_ARCH}) - Full Hook mode enabled")
else()
    message(STATUS "Detours library not found - Basic monitoring mode")
endif()

# Set output directory
set_target_properties(Xsjzb_launcher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(Xsjzb_hook PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install targets
install(TARGETS Xsjzb_launcher Xsjzb_hook
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION bin
)
