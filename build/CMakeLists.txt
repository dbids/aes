###############################################################################
## project setup ##############################################################
###############################################################################

# Specify minimum version
cmake_minimum_required(VERSION 3.5.0)

# specify project name
project(dbids_aes VERSION 0.1.0
        DESCRIPTION "dbids' basic AES implementation in C"
        LANGUAGES C)

###############################################################################
## target definitions #########################################################
###############################################################################

# compile libraries
# file(GLOB_RECURSE libs CONFIGURE_DEPENDS 
#   ${PROJECT_SOURCE_DIR}/../lib/*.h
#   ${PROJECT_SOURCE_DIR}/../lib/*.c)
# add_library(dbids_aes_lib ${libs})
add_library(aes STATIC ${PROJECT_SOURCE_DIR}/../lib/aes.c ${PROJECT_SOURCE_DIR}/../lib/aes.h)
add_library(debug STATIC ${PROJECT_SOURCE_DIR}/../lib/debug.c ${PROJECT_SOURCE_DIR}/../lib/debug.h)
add_library(ecb STATIC ${PROJECT_SOURCE_DIR}/../lib/ecb.c ${PROJECT_SOURCE_DIR}/../lib/ecb.h)

# compile executable
add_executable(dbids_aes_main ${PROJECT_SOURCE_DIR}/../src/main/main.c)

# link libraries and executable
target_link_libraries(dbids_aes_main PUBLIC aes debug ecb)

###############################################################################
## testing ####################################################################
###############################################################################
include(CTest)
enable_testing()

