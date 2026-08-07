cmake_minimum_required(VERSION 3.10)
project(ProjectDELTA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 1. Executable Definition (No changes needed here)
add_executable(reaper_app
    src/main.cpp
    libs/imgui/imgui.cpp
    libs/imgui/imgui_draw.cpp
    libs/imgui/imgui_tables.cpp
    libs/imgui/imgui_widgets.cpp
    libs/imgui/imgui_demo.cpp       
    libs/imgui/imgui_impl_glfw.cpp
    libs/imgui/imgui_impl_opengl3.cpp
)

# 2. Include Directories
# Ensure libs/glfw/include/GLFW/glfw3.h exists
target_include_directories(reaper_app PRIVATE
    src
    libs/imgui
    libs/glfw/include
)

# 3. Link Libraries
# CHANGED: Added 'resolv' for DNS resolution compatibility on some distros
# Kept your static GLFW link, but ensure the path is correct relative to CMakeLists.txt
target_link_libraries(reaper_app PRIVATE
    ${CMAKE_SOURCE_DIR}/libs/glfw/build/src/libglfw3.a
    GL
    X11
    pthread
    dl
    resolv  # <--- ADDED: Essential for getaddrinfo on some Linux systems
)

# Optional: If you get linker errors about GLFW, uncomment below to find it dynamically
# find_package(glfw3 REQUIRED)
# target_link_libraries(reaper_app PRIVATE glfw)   