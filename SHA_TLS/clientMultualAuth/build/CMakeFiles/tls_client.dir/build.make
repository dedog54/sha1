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
CMAKE_SOURCE_DIR = /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build

# Include any dependencies generated for this target.
include CMakeFiles/tls_client.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/tls_client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tls_client.dir/flags.make

CMakeFiles/tls_client.dir/main.cpp.o: CMakeFiles/tls_client.dir/flags.make
CMakeFiles/tls_client.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/tls_client.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tls_client.dir/main.cpp.o -c /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/main.cpp

CMakeFiles/tls_client.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tls_client.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/main.cpp > CMakeFiles/tls_client.dir/main.cpp.i

CMakeFiles/tls_client.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tls_client.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/main.cpp -o CMakeFiles/tls_client.dir/main.cpp.s

# Object files for target tls_client
tls_client_OBJECTS = \
"CMakeFiles/tls_client.dir/main.cpp.o"

# External object files for target tls_client
tls_client_EXTERNAL_OBJECTS =

tls_client: CMakeFiles/tls_client.dir/main.cpp.o
tls_client: CMakeFiles/tls_client.dir/build.make
tls_client: /usr/lib/x86_64-linux-gnu/libssl.so
tls_client: /usr/lib/x86_64-linux-gnu/libcrypto.so
tls_client: CMakeFiles/tls_client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable tls_client"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tls_client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tls_client.dir/build: tls_client

.PHONY : CMakeFiles/tls_client.dir/build

CMakeFiles/tls_client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tls_client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tls_client.dir/clean

CMakeFiles/tls_client.dir/depend:
	cd /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build /mnt/c/Users/sos98/vsCode/git/sha1/SHA_TLS/clientMultualAuth/build/CMakeFiles/tls_client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/tls_client.dir/depend

