# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:

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
CMAKE_COMMAND = /opt/local/bin/cmake

# The command to remove a file.
RM = /opt/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/david/Documents/Utils/AES-Encryption

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/david/Documents/Utils/AES-Encryption

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/opt/local/bin/ccmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/opt/local/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/david/Documents/Utils/AES-Encryption/CMakeFiles /Users/david/Documents/Utils/AES-Encryption//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/david/Documents/Utils/AES-Encryption/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named aes-tool

# Build rule for target.
aes-tool: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 aes-tool
.PHONY : aes-tool

# fast build rule for target.
aes-tool/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/build
.PHONY : aes-tool/fast

#=============================================================================
# Target rules for targets named argp-standalone

# Build rule for target.
argp-standalone: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 argp-standalone
.PHONY : argp-standalone

# fast build rule for target.
argp-standalone/fast:
	$(MAKE) $(MAKESILENT) -f 3rd_parties/argp/src/CMakeFiles/argp-standalone.dir/build.make 3rd_parties/argp/src/CMakeFiles/argp-standalone.dir/build
.PHONY : argp-standalone/fast

aes-tool.o: aes-tool.c.o
.PHONY : aes-tool.o

# target to build an object file
aes-tool.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/aes-tool.c.o
.PHONY : aes-tool.c.o

aes-tool.i: aes-tool.c.i
.PHONY : aes-tool.i

# target to preprocess a source file
aes-tool.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/aes-tool.c.i
.PHONY : aes-tool.c.i

aes-tool.s: aes-tool.c.s
.PHONY : aes-tool.s

# target to generate assembly for a file
aes-tool.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/aes-tool.c.s
.PHONY : aes-tool.c.s

aes_core.o: aes_core.c.o
.PHONY : aes_core.o

# target to build an object file
aes_core.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/aes_core.c.o
.PHONY : aes_core.c.o

aes_core.i: aes_core.c.i
.PHONY : aes_core.i

# target to preprocess a source file
aes_core.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/aes_core.c.i
.PHONY : aes_core.c.i

aes_core.s: aes_core.c.s
.PHONY : aes_core.s

# target to generate assembly for a file
aes_core.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes-tool.dir/build.make CMakeFiles/aes-tool.dir/aes_core.c.s
.PHONY : aes_core.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... aes-tool"
	@echo "... argp-standalone"
	@echo "... aes-tool.o"
	@echo "... aes-tool.i"
	@echo "... aes-tool.s"
	@echo "... aes_core.o"
	@echo "... aes_core.i"
	@echo "... aes_core.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

