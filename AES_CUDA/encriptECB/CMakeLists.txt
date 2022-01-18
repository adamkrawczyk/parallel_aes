cmake_minimum_required(VERSION 2.8.3)
project(cuda_aes)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CUDA REQUIRED)
# find_package(libcudard_static REQUIRED)

# to separate device functions in another file
set(CUDA_SEPARABLE_COMPILATION ON)

set(CUDA_NVCC_FLAGS ${CUDA_NVCC_FLAGS} -arch=sm_50 -rdc=true -std=c++17)

include_directories(
  headers
  ../../../../common/inc
)

set(sources sources/AES.cu sources/main.cu)
cuda_add_executable(encript_aes ${sources})
target_link_libraries(encript_aes PRIVATE librt.so -lstdc++fs)


add_executable(file_test sources/test_bin_file.cpp)
target_link_libraries(file_test PRIVATE -lstdc++fs)