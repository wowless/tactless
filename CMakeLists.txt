cmake_minimum_required(VERSION 3.0)
project(ctactless)
find_package(CURL REQUIRED)

add_library(tactless tactless.c tactless.h)
target_include_directories(tactless PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(tactless ${CURL_LIBRARIES})

add_executable(main main.c)
target_link_libraries(main tactless)
