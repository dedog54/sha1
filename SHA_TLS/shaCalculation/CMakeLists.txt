cmake_minimum_required(VERSION 3.12)
project(TLSClientExample)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Add executable
add_executable(sha main.cpp sha1.cpp)

# Include OpenSSL headers
target_include_directories(sha PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link against OpenSSL libraries and pthread
target_link_libraries(sha PRIVATE ${OPENSSL_LIBRARIES} Threads::Threads)


# Specify C++ version
target_compile_features(sha PRIVATE cxx_std_11)
