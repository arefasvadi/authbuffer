cmake_minimum_required(VERSION 3.12)

# Must be set before the project() command
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

project("authenticated_buffer")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Set the CMAKE_EXPORT_COMPILE_COMMANDS option
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
# Define different build types
set(CMAKE_BUILD_TYPE Debug) # Default to Debug; you can switch to Release
find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.10.0.zip
)
FetchContent_MakeAvailable(googletest)
function(set_project_default_compile_options target)
    target_compile_options(${target} PRIVATE
        "$<$<CONFIG:DEBUG>:-Wall;-Wextra;-Wpedantic;-g;-fsanitize=address;-fsanitize=undefined;-fsanitize=leak;-fno-omit-frame-pointer>"
        "$<$<CONFIG:RELEASE>:-O3;-DNDEBUG>"
    )

    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_link_options(${target} PRIVATE
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
        )
    endif()
endfunction()

add_library(untrusted STATIC 
${CMAKE_CURRENT_SOURCE_DIR}/src/BufferStore.cc
)
target_include_directories(untrusted PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
set_project_default_compile_options(untrusted)

add_library(bridge STATIC 
${CMAKE_CURRENT_SOURCE_DIR}/src/bridge.cc
)
target_include_directories(bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(
  bridge
  PRIVATE
  untrusted
)
set_project_default_compile_options(bridge)

add_library(tee STATIC 
${CMAKE_CURRENT_SOURCE_DIR}/src/SgxAuthBuffer.cc
)
target_include_directories(tee PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(tee PRIVATE include ${OPENSSL_INCLUDE_DIR})
target_link_libraries(
  tee
  PRIVATE
  bridge
)
target_link_libraries(tee PRIVATE ${OPENSSL_LIBRARIES})
set_project_default_compile_options(tee)

# Test setup
enable_testing()
add_executable(
  SgxAuthBufferTests
  tests/SgxAuthBufferTests.cc
)
target_link_libraries(
  SgxAuthBufferTests
  gtest_main
  tee
  untrusted
  bridge
  # Link with your main library if needed
)
target_include_directories(
  SgxAuthBufferTests PRIVATE
  include
)
set_project_default_compile_options(SgxAuthBufferTests)

include(GoogleTest)
gtest_discover_tests(SgxAuthBufferTests)
