set(This aes_test)
project(${This})
cmake_minimum_required(VERSION 3.8)
# include(Dart)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

set(Sources
    aes_test.cpp
    ../src/AES_CBC.cpp
    ../src/AES_ECB.cpp
    ../src/AES.cpp
)

add_executable(${This} ${Sources})
target_link_libraries(${This} PUBLIC
    gtest_main
    ${GTEST_LIBRARIES} 
    pthread
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
