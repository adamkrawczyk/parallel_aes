# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/eryk/Pulpit/parallel_aes/AES_CUDA

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild

# Include any dependencies generated for this target.
include encriptECB/CMakeFiles/encript_aes.dir/depend.make

# Include the progress variables for this target.
include encriptECB/CMakeFiles/encript_aes.dir/progress.make

# Include the compile flags for this target's objects.
include encriptECB/CMakeFiles/encript_aes.dir/flags.make

encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o.depend
encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o.cmake
encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o: ../encriptECB/sources/AES.cu
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building NVCC (Device) object encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o"
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources && /usr/bin/cmake -E make_directory /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/.
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources && /usr/bin/cmake -D verbose:BOOL=$(VERBOSE) -D build_configuration:STRING= -D generated_file:STRING=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/./encript_aes_generated_AES.cu.o -D generated_cubin_file:STRING=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/./encript_aes_generated_AES.cu.o.cubin.txt -P /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o.cmake

encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o.depend
encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o.cmake
encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o: ../encriptECB/sources/main.cu
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building NVCC (Device) object encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o"
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources && /usr/bin/cmake -E make_directory /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/.
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources && /usr/bin/cmake -D verbose:BOOL=$(VERBOSE) -D build_configuration:STRING= -D generated_file:STRING=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/./encript_aes_generated_main.cu.o -D generated_cubin_file:STRING=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/./encript_aes_generated_main.cu.o.cubin.txt -P /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o.cmake

encriptECB/CMakeFiles/encript_aes.dir/encript_aes_intermediate_link.o: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o
encriptECB/CMakeFiles/encript_aes.dir/encript_aes_intermediate_link.o: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building NVCC intermediate link file encriptECB/CMakeFiles/encript_aes.dir/encript_aes_intermediate_link.o"
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB && /usr/bin/nvcc -arch=sm_50 -rdc=true -std=c++17 -m64 -ccbin /usr/bin/cc -dlink /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/./encript_aes_generated_AES.cu.o /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/./encript_aes_generated_main.cu.o -o /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/./encript_aes_intermediate_link.o

# Object files for target encript_aes
encript_aes_OBJECTS =

# External object files for target encript_aes
encript_aes_EXTERNAL_OBJECTS = \
"/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o" \
"/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o" \
"/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/encript_aes_intermediate_link.o"

encriptECB/encript_aes: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o
encriptECB/encript_aes: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o
encriptECB/encript_aes: encriptECB/CMakeFiles/encript_aes.dir/encript_aes_intermediate_link.o
encriptECB/encript_aes: encriptECB/CMakeFiles/encript_aes.dir/build.make
encriptECB/encript_aes: /usr/lib/x86_64-linux-gnu/libcudart_static.a
encriptECB/encript_aes: /usr/lib/x86_64-linux-gnu/librt.so
encriptECB/encript_aes: encriptECB/CMakeFiles/encript_aes.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable encript_aes"
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/encript_aes.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
encriptECB/CMakeFiles/encript_aes.dir/build: encriptECB/encript_aes

.PHONY : encriptECB/CMakeFiles/encript_aes.dir/build

encriptECB/CMakeFiles/encript_aes.dir/clean:
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB && $(CMAKE_COMMAND) -P CMakeFiles/encript_aes.dir/cmake_clean.cmake
.PHONY : encriptECB/CMakeFiles/encript_aes.dir/clean

encriptECB/CMakeFiles/encript_aes.dir/depend: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_AES.cu.o
encriptECB/CMakeFiles/encript_aes.dir/depend: encriptECB/CMakeFiles/encript_aes.dir/sources/encript_aes_generated_main.cu.o
encriptECB/CMakeFiles/encript_aes.dir/depend: encriptECB/CMakeFiles/encript_aes.dir/encript_aes_intermediate_link.o
	cd /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/eryk/Pulpit/parallel_aes/AES_CUDA /home/eryk/Pulpit/parallel_aes/AES_CUDA/encriptECB /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB /home/eryk/Pulpit/parallel_aes/AES_CUDA/bild/encriptECB/CMakeFiles/encript_aes.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : encriptECB/CMakeFiles/encript_aes.dir/depend

