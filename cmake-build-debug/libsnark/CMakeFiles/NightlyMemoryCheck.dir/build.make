# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

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
CMAKE_COMMAND = /home/xinyue/clion-2017.3.4/bin/cmake/bin/cmake

# The command to remove a file.
RM = /home/xinyue/clion-2017.3.4/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/xinyue/libsnark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/xinyue/libsnark/cmake-build-debug

# Utility rule file for NightlyMemoryCheck.

# Include the progress variables for this target.
include libsnark/CMakeFiles/NightlyMemoryCheck.dir/progress.make

libsnark/CMakeFiles/NightlyMemoryCheck:
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && /home/xinyue/clion-2017.3.4/bin/cmake/bin/ctest -D NightlyMemoryCheck

NightlyMemoryCheck: libsnark/CMakeFiles/NightlyMemoryCheck
NightlyMemoryCheck: libsnark/CMakeFiles/NightlyMemoryCheck.dir/build.make

.PHONY : NightlyMemoryCheck

# Rule to build all files generated by this target.
libsnark/CMakeFiles/NightlyMemoryCheck.dir/build: NightlyMemoryCheck

.PHONY : libsnark/CMakeFiles/NightlyMemoryCheck.dir/build

libsnark/CMakeFiles/NightlyMemoryCheck.dir/clean:
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/NightlyMemoryCheck.dir/cmake_clean.cmake
.PHONY : libsnark/CMakeFiles/NightlyMemoryCheck.dir/clean

libsnark/CMakeFiles/NightlyMemoryCheck.dir/depend:
	cd /home/xinyue/libsnark/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark/cmake-build-debug /home/xinyue/libsnark/cmake-build-debug/libsnark /home/xinyue/libsnark/cmake-build-debug/libsnark/CMakeFiles/NightlyMemoryCheck.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/CMakeFiles/NightlyMemoryCheck.dir/depend

