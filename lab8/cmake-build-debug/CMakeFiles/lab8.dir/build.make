# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/d/Github/MCBivis/lab8

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/d/Github/MCBivis/lab8/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/lab8.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/lab8.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/lab8.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lab8.dir/flags.make

CMakeFiles/lab8.dir/main.c.o: CMakeFiles/lab8.dir/flags.make
CMakeFiles/lab8.dir/main.c.o: ../main.c
CMakeFiles/lab8.dir/main.c.o: CMakeFiles/lab8.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/d/Github/MCBivis/lab8/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/lab8.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/lab8.dir/main.c.o -MF CMakeFiles/lab8.dir/main.c.o.d -o CMakeFiles/lab8.dir/main.c.o -c /mnt/d/Github/MCBivis/lab8/main.c

CMakeFiles/lab8.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/lab8.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/d/Github/MCBivis/lab8/main.c > CMakeFiles/lab8.dir/main.c.i

CMakeFiles/lab8.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/lab8.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/d/Github/MCBivis/lab8/main.c -o CMakeFiles/lab8.dir/main.c.s

# Object files for target lab8
lab8_OBJECTS = \
"CMakeFiles/lab8.dir/main.c.o"

# External object files for target lab8
lab8_EXTERNAL_OBJECTS =

lab8: CMakeFiles/lab8.dir/main.c.o
lab8: CMakeFiles/lab8.dir/build.make
lab8: CMakeFiles/lab8.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/d/Github/MCBivis/lab8/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable lab8"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lab8.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/lab8.dir/build: lab8
.PHONY : CMakeFiles/lab8.dir/build

CMakeFiles/lab8.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lab8.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lab8.dir/clean

CMakeFiles/lab8.dir/depend:
	cd /mnt/d/Github/MCBivis/lab8/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/d/Github/MCBivis/lab8 /mnt/d/Github/MCBivis/lab8 /mnt/d/Github/MCBivis/lab8/cmake-build-debug /mnt/d/Github/MCBivis/lab8/cmake-build-debug /mnt/d/Github/MCBivis/lab8/cmake-build-debug/CMakeFiles/lab8.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/lab8.dir/depend

