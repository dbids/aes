###############################################################################
## project setup ##############################################################
###############################################################################

# Specify minimum version
cmake_minimum_required(VERSION 3.15...3.27)

# specify project name
project(dbids_aes VERSION 0.1.0
        DESCRIPTION "dbids' basic AES implementation in C"
        LANGUAGES C)

### Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory. Feel free to remove CMakeCache.txt and CMakeFiles.")
endif()

###############################################################################
## target definitions #########################################################
###############################################################################

#### ADD SUBDIRECTORIES ####

# The compiled library code is here
add_subdirectory(src)

# The executable code is here
add_subdirectory(apps)

# compile libraries

# file(GLOB_RECURSE libs CONFIGURE_DEPENDS 
#   ${PROJECT_SOURCE_DIR}/../lib/*.h
#   ${PROJECT_SOURCE_DIR}/../lib/*.c)
# add_library(dbids_aes_lib ${libs})

# add_library(aes STATIC ${PROJECT_SOURCE_DIR}/../lib/aes.c ${PROJECT_SOURCE_DIR}/../lib/aes.h)
# add_library(debug STATIC ${PROJECT_SOURCE_DIR}/../lib/debug.c ${PROJECT_SOURCE_DIR}/../lib/debug.h)
# add_library(ecb STATIC ${PROJECT_SOURCE_DIR}/../lib/ecb.c ${PROJECT_SOURCE_DIR}/../lib/ecb.h)

# compile executable
# add_executable(dbids_aes_main ${PROJECT_SOURCE_DIR}/../src/main/main.c)

# link libraries and executable
# target_link_libraries(dbids_aes_main PUBLIC aes debug ecb)

###############################################################################
## testing ####################################################################
###############################################################################

# Testing only available if this is the main app
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  # Testing only available if this is the main app
  # Note this needs to be done in the main CMakeLists
  # since it calls enable_testing, which must be in the
  # main CMakeLists.
  include(CTest)

  # Add tests subdirectory
  add_subdirectory(tests)
endif()


