# Create executable
add_executable(main main.c)

# Add include dirs for libs
target_include_directories(main PUBLIC ${PROJECT_SOURCE_DIR}/src)

# Add gcc compiler version
set_property(TARGET main PROPERTY C_STANDARD 11)

# Link to aes library
target_link_libraries(main PRIVATE aes_lib ecb_lib debug_lib)
