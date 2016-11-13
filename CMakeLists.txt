cmake_minimum_required(VERSION 3.6)
project(uses-sse2)

find_library(udis86 udis86)
add_executable(uses-sse2 uses-sse2.c)
target_link_libraries(uses-sse2 ${udis86})

install(TARGETS uses-sse2 RUNTIME DESTINATION bin)
