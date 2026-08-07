# Create build directory
mkdir build && cd build

# Configure
cmake ..

# Build
make -j4

# Run
./reaper