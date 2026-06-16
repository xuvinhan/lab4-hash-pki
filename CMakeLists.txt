cmake_minimum_required(VERSION 3.20)

project(Lab4_Hash_PKI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(hashtool
    src/main.cpp
    src/hash_utils.cpp
    src/file_utils.cpp
    src/x509_utils.cpp
    src/length_extension_utils.cpp
    src/hmac_utils.cpp
    src/md5_collision_utils.cpp
)

target_include_directories(hashtool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(hashtool PRIVATE
    OpenSSL::Crypto
)
