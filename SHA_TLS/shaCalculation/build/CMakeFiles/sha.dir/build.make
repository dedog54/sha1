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
CMAKE_SOURCE_DIR = /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build

# Include any dependencies generated for this target.
include CMakeFiles/sha.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/sha.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sha.dir/flags.make

CMakeFiles/sha.dir/main.cpp.o: CMakeFiles/sha.dir/flags.make
CMakeFiles/sha.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/sha.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/sha.dir/main.cpp.o -c /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/main.cpp

CMakeFiles/sha.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sha.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/main.cpp > CMakeFiles/sha.dir/main.cpp.i

CMakeFiles/sha.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sha.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/main.cpp -o CMakeFiles/sha.dir/main.cpp.s

CMakeFiles/sha.dir/sha1.cpp.o: CMakeFiles/sha.dir/flags.make
CMakeFiles/sha.dir/sha1.cpp.o: ../sha1.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/sha.dir/sha1.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/sha.dir/sha1.cpp.o -c /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/sha1.cpp

CMakeFiles/sha.dir/sha1.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sha.dir/sha1.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/sha1.cpp > CMakeFiles/sha.dir/sha1.cpp.i

CMakeFiles/sha.dir/sha1.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sha.dir/sha1.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/sha1.cpp -o CMakeFiles/sha.dir/sha1.cpp.s

# Object files for target sha
sha_OBJECTS = \
"CMakeFiles/sha.dir/main.cpp.o" \
"CMakeFiles/sha.dir/sha1.cpp.o"

# External object files for target sha
sha_EXTERNAL_OBJECTS =

sha: CMakeFiles/sha.dir/main.cpp.o
sha: CMakeFiles/sha.dir/sha1.cpp.o
sha: CMakeFiles/sha.dir/build.make
sha: /usr/lib/x86_64-linux-gnu/libssl.so
sha: /usr/lib/x86_64-linux-gnu/libcrypto.so
sha: CMakeFiles/sha.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable sha"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sha.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sha.dir/build: sha

.PHONY : CMakeFiles/sha.dir/build

CMakeFiles/sha.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sha.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sha.dir/clean

CMakeFiles/sha.dir/depend:
	cd /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/shaCalculation/build/CMakeFiles/sha.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sha.dir/depend

