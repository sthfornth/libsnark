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

# Include any dependencies generated for this target.
include depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/depend.make

# Include the progress variables for this target.
include depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/progress.make

# Include the compile flags for this target's objects.
include depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/flags.make

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/flags.make
depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o: ../depends/gtest/googletest/src/gtest_main.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/xinyue/libsnark/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o"
	cd /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gtest_main.dir/src/gtest_main.cc.o -c /home/xinyue/libsnark/depends/gtest/googletest/src/gtest_main.cc

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gtest_main.dir/src/gtest_main.cc.i"
	cd /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/xinyue/libsnark/depends/gtest/googletest/src/gtest_main.cc > CMakeFiles/gtest_main.dir/src/gtest_main.cc.i

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gtest_main.dir/src/gtest_main.cc.s"
	cd /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/xinyue/libsnark/depends/gtest/googletest/src/gtest_main.cc -o CMakeFiles/gtest_main.dir/src/gtest_main.cc.s

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.requires:

.PHONY : depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.requires

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.provides: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.requires
	$(MAKE) -f depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build.make depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.provides.build
.PHONY : depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.provides

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.provides.build: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o


# Object files for target gtest_main
gtest_main_OBJECTS = \
"CMakeFiles/gtest_main.dir/src/gtest_main.cc.o"

# External object files for target gtest_main
gtest_main_EXTERNAL_OBJECTS =

depends/gtest/googlemock/gtest/libgtest_maind.a: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o
depends/gtest/googlemock/gtest/libgtest_maind.a: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build.make
depends/gtest/googlemock/gtest/libgtest_maind.a: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/xinyue/libsnark/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libgtest_maind.a"
	cd /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -P CMakeFiles/gtest_main.dir/cmake_clean_target.cmake
	cd /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gtest_main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build: depends/gtest/googlemock/gtest/libgtest_maind.a

.PHONY : depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/requires: depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o.requires

.PHONY : depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/requires

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/clean:
	cd /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -P CMakeFiles/gtest_main.dir/cmake_clean.cmake
.PHONY : depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/clean

depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/depend:
	cd /home/xinyue/libsnark/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xinyue/libsnark /home/xinyue/libsnark/depends/gtest/googletest /home/xinyue/libsnark/cmake-build-debug /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest /home/xinyue/libsnark/cmake-build-debug/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/depend

