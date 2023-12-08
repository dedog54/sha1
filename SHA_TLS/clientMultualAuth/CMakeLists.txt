cmake_minimum_required(VERSION 3.12)
project(TLSClientExample)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Add executable
add_executable(tls_client main.cpp sha1.cpp tls.cpp)

# Include OpenSSL headers
target_include_directories(tls_client PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link against OpenSSL libraries
target_link_libraries(tls_client PRIVATE ${OPENSSL_LIBRARIES} Threads::Threads)

# Specify C++ version
target_compile_features(tls_client PRIVATE cxx_std_11)

