cmake_minimum_required(VERSION 3.10)
project(Sniffer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)

add_library(sniffer_lib
        src/sniffer.cpp
        src/sniffer.h
)

add_executable(main
        src/main.cpp
)
target_link_libraries(main sniffer_lib)

add_executable(tests
        tests/test.cpp
)
target_link_libraries(tests
        PRIVATE
        sniffer_lib
        GTest::GTest
        GTest::Main
)

enable_testing()
add_test(NAME MyTests COMMAND tests)