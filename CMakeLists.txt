cmake_minimum_required(VERSION 3.28)
project(DLLMemLdr C)

set(CMAKE_C_STANDARD 11)

add_library(DLLMemLdr STATIC DllMemLdr.c)

add_executable(testing_from_disk tests/TestLdrLoadDllFromDisk.c)
add_executable(testing_from_web tests/TestLdrLoadDllFromWeb.c)
add_executable(testing_inject_dll tests/TestLdrInjectDllProcHandle.c)

target_link_libraries(testing_from_web wininet)

target_link_libraries(testing_from_disk DLLMemLdr)
target_link_libraries(testing_from_web DLLMemLdr)
target_link_libraries(testing_inject_dll DLLMemLdr)

