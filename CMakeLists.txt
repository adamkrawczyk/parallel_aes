set(This AES_CPP)
project(${This})
cmake_minimum_required(VERSION 3.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -fext-numeric-literals -Wpedantic -Wall -Wextra")

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/AES_CPP/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/AES_CPP/include)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})


INCLUDE_DIRECTORIES(AES_CPP/include)

#Header files
file(GLOB_RECURSE HEADER_FILES AES_CPP/include/*.hpp AES_CPP/include/*.h)
file(GLOB AES_CPP_SOURCE_FILES
     "AES_CPP/src/*.c"
     "AES_CPP/src/*.cpp"
     "AES_CPP/src/*.cxx"
)


# The following folder will be included
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories(${PROJECT_SOURCE_DIR}/include)
link_directories(${PROJECT_SOURCE_DIR}/lib)

# Header files
include_directories(include)

# Exec files

add_executable(main ${SOURCE_DIR}/main.cpp ${AES_CPP_SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(main)


## Test

enable_testing()
add_library(${This} STATIC ${AES_CPP_SOURCE_FILES} ${HEADER_FILES})
add_subdirectory(AES_CPP/test)
# endif()
