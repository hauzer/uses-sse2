find_library(udis86 udis86)
add_executable(uses-sse2 uses-sse2.c)
target_link_libraries(uses-sse2 ${udis86})
