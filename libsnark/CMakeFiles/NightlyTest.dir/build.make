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

# Utility rule file for NightlyTest.

# Include the progress variables for this target.
include libsnark/CMakeFiles/NightlyTest.dir/progress.make

libsnark/CMakeFiles/NightlyTest:
	cd /home/xinyue/libsnark/libsnark && /usr/local/bin/ctest -D NightlyTest

NightlyTest: libsnark/CMakeFiles/NightlyTest
NightlyTest: libsnark/CMakeFiles/NightlyTest.dir/build.make

.PHONY : NightlyTest

# Rule to build all files generated by this target.
libsnark/CMakeFiles/NightlyTest.dir/build: NightlyTest

.PHONY : libsnark/CMakeFiles/NightlyTest.dir/build

libsnark/CMakeFiles/NightlyTest.dir/clean:
	cd /home/xinyue/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/NightlyTest.dir/cmake_clean.cmake
.PHONY : libsnark/CMakeFiles/NightlyTest.dir/clean

libsnark/CMakeFiles/NightlyTest.dir/depend:
	cd /home/xinyue/libsnark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark/libsnark/CMakeFiles/NightlyTest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/CMakeFiles/NightlyTest.dir/depend

