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
include libsnark/CMakeFiles/test_knapsack_gadget.dir/depend.make

# Include the progress variables for this target.
include libsnark/CMakeFiles/test_knapsack_gadget.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/CMakeFiles/test_knapsack_gadget.dir/flags.make

libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o: libsnark/CMakeFiles/test_knapsack_gadget.dir/flags.make
libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o: ../libsnark/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/xinyue/libsnark/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o"
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o -c /home/xinyue/libsnark/libsnark/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp

libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.i"
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/xinyue/libsnark/libsnark/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp > CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.i

libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.s"
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/xinyue/libsnark/libsnark/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp -o CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.s

libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.requires:

.PHONY : libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.requires

libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.provides: libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.requires
	$(MAKE) -f libsnark/CMakeFiles/test_knapsack_gadget.dir/build.make libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.provides.build
.PHONY : libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.provides

libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.provides.build: libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o


# Object files for target test_knapsack_gadget
test_knapsack_gadget_OBJECTS = \
"CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o"

# External object files for target test_knapsack_gadget
test_knapsack_gadget_EXTERNAL_OBJECTS =

libsnark/test_knapsack_gadget: libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o
libsnark/test_knapsack_gadget: libsnark/CMakeFiles/test_knapsack_gadget.dir/build.make
libsnark/test_knapsack_gadget: libsnark/libsnarkd.a
libsnark/test_knapsack_gadget: depends/libff/libff/libffd.a
libsnark/test_knapsack_gadget: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/test_knapsack_gadget: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/test_knapsack_gadget: /usr/lib/x86_64-linux-gnu/libgmpxx.so
libsnark/test_knapsack_gadget: depends/libzmd.a
libsnark/test_knapsack_gadget: libsnark/CMakeFiles/test_knapsack_gadget.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/xinyue/libsnark/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_knapsack_gadget"
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_knapsack_gadget.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/CMakeFiles/test_knapsack_gadget.dir/build: libsnark/test_knapsack_gadget

.PHONY : libsnark/CMakeFiles/test_knapsack_gadget.dir/build

libsnark/CMakeFiles/test_knapsack_gadget.dir/requires: libsnark/CMakeFiles/test_knapsack_gadget.dir/gadgetlib1/gadgets/hashes/knapsack/tests/test_knapsack_gadget.cpp.o.requires

.PHONY : libsnark/CMakeFiles/test_knapsack_gadget.dir/requires

libsnark/CMakeFiles/test_knapsack_gadget.dir/clean:
	cd /home/xinyue/libsnark/cmake-build-debug/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/test_knapsack_gadget.dir/cmake_clean.cmake
.PHONY : libsnark/CMakeFiles/test_knapsack_gadget.dir/clean

libsnark/CMakeFiles/test_knapsack_gadget.dir/depend:
	cd /home/xinyue/libsnark/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xinyue/libsnark /home/xinyue/libsnark/libsnark /home/xinyue/libsnark/cmake-build-debug /home/xinyue/libsnark/cmake-build-debug/libsnark /home/xinyue/libsnark/cmake-build-debug/libsnark/CMakeFiles/test_knapsack_gadget.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/CMakeFiles/test_knapsack_gadget.dir/depend

