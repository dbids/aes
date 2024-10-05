# Specify minimum version
cmake_minimum_required(VERSION 3.27)

#specify project name
project(dbids_aes C_STANDARD)

# create libraries
add_library(aes SHARED ${CMAKE_CURRENT_SOURCE_DIR}/C/aes.h ${CMAKE_CURRENT_SOURCE_DIR}/C/aes.c)
add_library(debug SHARED ${CMAKE_CURRENT_SOURCE_DIR}/C/debug.h ${CMAKE_CURRENT_SOURCE_DIR}/C/debug.c)
add_library(debug SHARED ${CMAKE_CURRENT_SOURCE_DIR}/C/ecb.h ${CMAKE_CURRENT_SOURCE_DIR}/C/ecb.c)

# create executable
add_executable(test ${CMAKE_CURRENT_SOURCE_DIR}/C/main.c)
