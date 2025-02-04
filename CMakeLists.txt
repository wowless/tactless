cmake_minimum_required(VERSION 3.5)

option(BUILD_SHARED_LIBS "build library as shared" OFF)

project(ctactless)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

add_library(tactless tactless.c tactless.h)
set_target_properties(tactless PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
target_link_libraries(tactless PRIVATE CURL::libcurl OpenSSL::Crypto ZLIB::ZLIB)

add_executable(main main.c)
target_link_libraries(main tactless)
