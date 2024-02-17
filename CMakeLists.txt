cmake_minimum_required(VERSION 3.5)

set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

set(CMAKE_C_VISIBILITY_PRESET hidden)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

include(GenerateExportHeader)

project(ctactless LANGUAGES C)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_library(tactless tactless.c tactless.h)
generate_export_header(tactless)
target_include_directories(tactless PUBLIC ${PROJECT_BINARY_DIR})
target_link_libraries(tactless PRIVATE CURL::libcurl OpenSSL::Crypto ZLIB::ZLIB)

add_executable(main main.c)
target_link_libraries(main tactless)
