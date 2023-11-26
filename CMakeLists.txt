cmake_minimum_required(VERSION 3.12)
project("authenticated_buffer")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Set the CMAKE_EXPORT_COMPILE_COMMANDS option
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)

set(SOURCES
    src/main.cc
)

set(HEADERS
    include/merkle.h
)

# Create an executable from the source files
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# target_compile_options(${PROJECT_NAME} PUBLIC "-lssl -lcrypto")

# OpenSSL
target_include_directories(${PROJECT_NAME} PRIVATE include ${OpenSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${OpenSSL_LIBRARIES})

# Specify include directories
# target_include_directories(${PROJECT_NAME} PRIVATE include)

# Optional: Add additional compiler flags if needed
# target_compile_options(${PROJECT_NAME} PRIVATE ...)

# Optional: Add additional libraries if needed
# target_link_libraries(${PROJECT_NAME} ...)

# Optional: Specify output directory for the executable
# set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
