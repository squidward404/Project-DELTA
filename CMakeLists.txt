cmake_minimum_required(VERSION 3.10)
project(ProjectDELTA)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 1. Create the executable and list ALL .cpp files needed
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

# 2. Tell the compiler where to look for header files (.h)
target_include_directories(reaper_app PRIVATE
    src
    libs/imgui
    libs/glfw/include
)

# 3. Link the compiled GLFW library and Linux system libraries
target_link_libraries(reaper_app PRIVATE
    ${CMAKE_SOURCE_DIR}/libs/glfw/build/src/libglfw3.a
    GL
    X11
    pthread
    dl
)