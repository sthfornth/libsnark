# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.11

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
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/xinyue/libsnark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/xinyue/libsnark

# Include any dependencies generated for this target.
include libsnark/CMakeFiles/profile_ram_zksnark.dir/depend.make

# Include the progress variables for this target.
include libsnark/CMakeFiles/profile_ram_zksnark.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/CMakeFiles/profile_ram_zksnark.dir/flags.make

libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o: libsnark/CMakeFiles/profile_ram_zksnark.dir/flags.make
libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o: libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/xinyue/libsnark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o"
	cd /home/xinyue/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o -c /home/xinyue/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp

libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i"
	cd /home/xinyue/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/xinyue/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp > CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i

libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s"
	cd /home/xinyue/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/xinyue/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp -o CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s

# Object files for target profile_ram_zksnark
profile_ram_zksnark_OBJECTS = \
"CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o"

# External object files for target profile_ram_zksnark
profile_ram_zksnark_EXTERNAL_OBJECTS =

libsnark/profile_ram_zksnark: libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o
libsnark/profile_ram_zksnark: libsnark/CMakeFiles/profile_ram_zksnark.dir/build.make
libsnark/profile_ram_zksnark: libsnark/libsnarkd.a
libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libboost_program_options.so
libsnark/profile_ram_zksnark: depends/libff/libff/libffd.a
libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmpxx.so
libsnark/profile_ram_zksnark: depends/libzmd.a
libsnark/profile_ram_zksnark: libsnark/CMakeFiles/profile_ram_zksnark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/xinyue/libsnark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_ram_zksnark"
	cd /home/xinyue/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_ram_zksnark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/CMakeFiles/profile_ram_zksnark.dir/build: libsnark/profile_ram_zksnark

.PHONY : libsnark/CMakeFiles/profile_ram_zksnark.dir/build

libsnark/CMakeFiles/profile_ram_zksnark.dir/clean:
	cd /home/xinyue/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/profile_ram_zksnark.dir/cmake_clean.cmake
.PHONY : libsnark/CMakeFiles/profile_ram_zksnark.dir/clean

libsnark/CMakeFiles/profile_ram_zksnark.dir/depend:
	cd /home/xinyue/libsnark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/CMakeFiles/profile_ram_zksnark.dir/depend

