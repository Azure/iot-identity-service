#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)
project(aziottpm)
set (aziottpm_VERSION_MAJOR 1)
set (aziottpm_VERSION_MINOR 0)
set (aziottpm_VERSION_PATCH 0)

#Use solution folders.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include_directories(./deps/c-shared/inc)
include_directories(./deps/c-shared/deps/azure-macro-utils-c/inc)
include_directories(./deps/c-shared/deps/umock-c/inc)
include_directories(./deps/utpm/inc)
include_directories(. ./inc)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(source_c_files
    ./src/aziot_tpm.c
    ./src/hsm_client_tpm_device.c
    ./src/hsm_log.c
)

set(source_h_files
    ./inc/aziot_tpm.h
    ./inc/hsm_client_data.h
    ./src/hsm_client_tpm_device.h
    ./src/hsm_log.h
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fPIC -Wall -Werror -Wextra -Wformat=2 -Wformat-security -std=c99 ")

# suppress clang compiler warnings complaining about calls to vsnprintf
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=format-nonliteral")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fPIC -Wall -Werror -Wextra -Wformat=2 -Wformat-security ")

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wtrampolines -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 ")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wtrampolines -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 ")
endif()

add_definitions(-DDONT_USE_UPLOADTOBLOB=ON)

add_library(aziottpm STATIC ${source_c_files} ${source_in_mem_store_c_files} ${source_h_files})

if (run_unittests)
    enable_testing()
    set(save_ut ${run_unittests})
    set(run_unittests OFF CACHE BOOL "unittests" FORCE)
endif(run_unittests)

add_subdirectory(./deps/c-shared EXCLUDE_FROM_ALL)
add_subdirectory(./deps/utpm EXCLUDE_FROM_ALL)

if (save_ut)
    set(run_unittests ${save_ut} CACHE BOOL "unittests" FORCE)
endif(save_ut)

target_link_libraries(aziottpm aziotsharedutil utpm ${OPENSSL_LIBRARIES})

if (${run_unittests})
    add_subdirectory(tests)
endif()

set_target_properties(aziottpm PROPERTIES
        VERSION ${aziottpm_VERSION_MAJOR}.${aziottpm_VERSION_MINOR}.${aziottpm_VERSION_PATCH}
        SOVERSION 1)
