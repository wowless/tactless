cmake_minimum_required(VERSION 3.5)

set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(ctactless)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_library(tactless tactless.c tactless.h)
target_include_directories(tactless PUBLIC ${PROJECT_BINARY_DIR})
target_link_libraries(tactless PRIVATE CURL::libcurl OpenSSL::Crypto ZLIB::ZLIB)

include(GenerateExportHeader)
generate_export_header(tactless)

add_executable(main main.c)
target_link_libraries(main tactless)
