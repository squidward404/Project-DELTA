cmake_minimum_required(VERSION 3.10)
project(ProjectDELTA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 1. Executable Definition
# Note: DNSResolve.cpp is NOT listed here because it is now header-only
add_executable(reaper
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
# 'include' folder added so main.cpp can find "DNSResolve.h"
target_include_directories(reaper PRIVATE
    src
    include
    libs/imgui
    libs/glfw/include
)

# 3. Link Libraries
target_link_libraries(reaper PRIVATE
    ${CMAKE_SOURCE_DIR}/libs/glfw/build/src/libglfw3.a
    GL
    X11
    pthread
    dl
    resolv  # Required for DNS on Linux
)   