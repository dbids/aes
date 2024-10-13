### compile libraries ###

# Make libraries
add_library(aes_lib STATIC aes.c aes.h)
add_library(debug_lib STATIC debug.c debug.h)
add_library(ecb_lib STATIC ecb.c ecb.h)
