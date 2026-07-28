1. Create a build folder and go inside it:
mkdir build && cd build
2. Tell CMake to read your CMakeLists.txt and generate the build files:
cmake ..
3. Compile the code:
make
Step 3: Run your app!
If make finishes without any red error text, your executable has been created inside the build folder. You can run it right now by typing:
./reaper_app
From now on, whenever you change your code, you don't need to run cmake .. again. You only need to run make inside the build folder to recompile your changes!