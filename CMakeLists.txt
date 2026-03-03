# =============================================================================
# CMakeLists.txt — CyberSec Multitool v3.0
#
# Requirements:
#   - CMake 3.20+
#   - MSVC 19.29+ (VS 2019 16.10+) or Clang-cl with MSVC STL
#   - Windows 10 SDK (10.0.19041.0 or later for bcrypt / wintrust)
#
# Build (Release):
#   cmake -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# Build (Debug):
#   cmake --build build --config Debug
# =============================================================================

cmake_minimum_required(VERSION 3.20)

project(CyberSecMultitool
    VERSION 3.0
    DESCRIPTION "Professional Windows Cybersecurity Utility"
    LANGUAGES CXX)

# ── C++20 standard (required for jthread, stop_token, concepts, ranges) ──────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Enforce Windows platform ──────────────────────────────────────────────────
if (NOT WIN32)
    message(FATAL_ERROR "CyberSec Multitool is Windows-only.")
endif()

# ── Source files ──────────────────────────────────────────────────────────────
add_executable(${PROJECT_NAME}
    main.cpp
)

# ── Include directories ───────────────────────────────────────────────────────
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ── Windows SDK libraries ─────────────────────────────────────────────────────
# (pragma comment(lib, ...) handles most of these, but explicit linking is
#  more portable across generators.)
target_link_libraries(${PROJECT_NAME} PRIVATE
    ws2_32          # Winsock 2
    bcrypt          # Windows CNG (MD5, SHA-256, AES-256)
    pdh             # Performance Data Helper (CPU stats)
    psapi           # Process memory info
    wintrust        # Authenticode signature verification
    crypt32         # Required by wintrust
    shlwapi         # Shell utility functions
)

# ── MSVC compiler flags ───────────────────────────────────────────────────────
if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4             # High warning level
        /WX             # Warnings as errors (keep the code clean)
        /permissive-    # Strict standards conformance
        /Zc:__cplusplus # Report correct C++ version to __cplusplus macro
        /MP             # Multi-processor compilation
        /utf-8          # Source files are UTF-8
        # Suppress a few noisy MSVC warnings:
        /wd4100         # unreferenced formal parameter (some Win32 callbacks)
        /wd4996         # 'deprecated' POSIX names used in Winsock code
    )
    # Release: maximise speed, enable link-time optimisation
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/O2 /GL /Oi /Gy>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/LTCG>
    )
endif()

# ── Windows subsystem: CONSOLE (required for terminal output) ─────────────────
set_target_properties(${PROJECT_NAME} PROPERTIES
    WIN32_EXECUTABLE FALSE   # Force console subsystem
)

# ── Preprocessor definitions ──────────────────────────────────────────────────
target_compile_definitions(${PROJECT_NAME} PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX                # Prevent Windows.h from defining min/max macros
    _WIN32_WINNT=0x0A00     # Target Windows 10
    NTDDI_VERSION=0x0A000007 # Windows 10 1903
)

# ── Post-build message ────────────────────────────────────────────────────────
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo
    "[BUILD OK] CyberSecMultitool.exe ready in ${CMAKE_BINARY_DIR}"
)

# ── Install rules (optional) ──────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin)
