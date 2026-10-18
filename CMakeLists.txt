cmake_minimum_required(VERSION 3.20)

project(NetSecure
    VERSION 1.0.0
    DESCRIPTION "Post-quantum session layer (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM) on top of Network"
    LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "NetSecure currently supports Windows only (Network is IOCP).")
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(BUILD_SHARED_LIBS "Build NetSecure and its sibling dependencies as shared libraries" ON)
option(NETSECURE_BUILD_EXAMPLES "Build the secure echo server/client examples" ON)
option(NETSECURE_BUILD_TESTS "Build the NetSecure test suite (CTest)" ON)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Dependencies: in-workspace OpenSSL + sibling projects
# ---------------------------------------------------------------------------
set(_NETSECURE_TOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../tools")
if(NOT OPENSSL_ROOT_DIR AND EXISTS "${_NETSECURE_TOOLS_DIR}/openssl-install")
    set(OPENSSL_ROOT_DIR "${_NETSECURE_TOOLS_DIR}/openssl-install"
        CACHE PATH "OpenSSL install prefix" FORCE)
endif()

# Network: transport + framing + ICodec hook (crypto-free).
set(NETWORK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(NETWORK_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(../Network ${CMAKE_BINARY_DIR}/Network)

# Crypto: the stateless engines (AES-256-GCM, ML-KEM-768, HKDF).
set(CRYPTO_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CRYPTO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(../Crypto ${CMAKE_BINARY_DIR}/Crypto)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(NetSecure
    src/AesGcmCodec.cpp
    src/Handshake.cpp
)

target_include_directories(NetSecure PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# NetSecure is the ONLY place where Network and Crypto meet.
target_link_libraries(NetSecure PUBLIC Network Crypto)

if(MINGW)
    # Static builds need the executables to resolve OpenSSL's own imports
    # (ws2_32 etc.). Appending these after the dependency chain keeps GNU
    # ld's left-to-right archive scan happy (Crypto convention).
    target_link_libraries(NetSecure PUBLIC ws2_32 gdi32 crypt32)
endif()

# Import/export semantics (Crypto convention).
if(BUILD_SHARED_LIBS)
    target_compile_definitions(NetSecure PRIVATE NETSECURE_EXPORTS)
else()
    target_compile_definitions(NetSecure PUBLIC NETSECURE_STATIC)
endif()

set_target_properties(NetSecure PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Copy the MinGW runtime DLLs next to an executable (same helper as Crypto).
function(netsecure_copy_mingw_runtime target)
    if(NOT MINGW)
        return()
    endif()
    get_filename_component(_NETSECURE_MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(_NETSECURE_MINGW_RUNTIME_DLLS)
    foreach(_runtimeDll IN ITEMS libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll)
        if(EXISTS "${_NETSECURE_MINGW_BIN_DIR}/${_runtimeDll}")
            list(APPEND _NETSECURE_MINGW_RUNTIME_DLLS "${_NETSECURE_MINGW_BIN_DIR}/${_runtimeDll}")
        endif()
    endforeach()
    if(_NETSECURE_MINGW_RUNTIME_DLLS)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_NETSECURE_MINGW_RUNTIME_DLLS}
                    $<TARGET_FILE_DIR:${target}>
            COMMENT "Copying MinGW runtime DLLs next to ${target}")
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(NETSECURE_BUILD_EXAMPLES)
    add_executable(secure_echo_server examples/secure_echo_server.cpp)
    target_link_libraries(secure_echo_server PRIVATE NetSecure)
    set_target_properties(secure_echo_server PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    netsecure_copy_mingw_runtime(secure_echo_server)

    add_executable(secure_echo_client examples/secure_echo_client.cpp)
    target_link_libraries(secure_echo_client PRIVATE NetSecure)
    set_target_properties(secure_echo_client PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    netsecure_copy_mingw_runtime(secure_echo_client)
endif()

# ---------------------------------------------------------------------------
# Tests (CTest)
# ---------------------------------------------------------------------------
include(CTest)
if(NETSECURE_BUILD_TESTS AND BUILD_TESTING)
    add_executable(NetSecure_tests tests/test_netsecure.cpp)
    target_link_libraries(NetSecure_tests PRIVATE NetSecure)
    set_target_properties(NetSecure_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    netsecure_copy_mingw_runtime(NetSecure_tests)

    add_test(NAME NetSecure_tests COMMAND NetSecure_tests)
    set_tests_properties(NetSecure_tests PROPERTIES TIMEOUT 120)
endif()

# ---------------------------------------------------------------------------
# Install rules
# ---------------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS NetSecure EXPORT NetSecureTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT NetSecureTargets
    FILE NetSecureTargets.cmake
    NAMESPACE NetSecure::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetSecure
)
