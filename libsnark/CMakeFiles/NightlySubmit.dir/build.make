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

# Utility rule file for NightlySubmit.

# Include the progress variables for this target.
include libsnark/CMakeFiles/NightlySubmit.dir/progress.make

libsnark/CMakeFiles/NightlySubmit:
	cd /home/xinyue/libsnark/libsnark && /usr/local/bin/ctest -D NightlySubmit

NightlySubmit: libsnark/CMakeFiles/NightlySubmit
NightlySubmit: libsnark/CMakeFiles/NightlySubmit.dir/build.make

.PHONY : NightlySubmit

# Rule to build all files generated by this target.
libsnark/CMakeFiles/NightlySubmit.dir/build: NightlySubmit

.PHONY : libsnark/CMakeFiles/NightlySubmit.dir/build

libsnark/CMakeFiles/NightlySubmit.dir/clean:
	cd /home/xinyue/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/NightlySubmit.dir/cmake_clean.cmake
.PHONY : libsnark/CMakeFiles/NightlySubmit.dir/clean

libsnark/CMakeFiles/NightlySubmit.dir/depend:
	cd /home/xinyue/libsnark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark/libsnark/CMakeFiles/NightlySubmit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/CMakeFiles/NightlySubmit.dir/depend

