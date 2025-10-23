cmake_minimum_required(VERSION 3.16)
project(ConfigCollector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Network)

# Source files
set(SOURCES
    src/main.cpp
    src/Utils.cpp
    src/HttpHelper.cpp
    src/ProxyBean.cpp
    src/SubParser.cpp
    3rdparty/base64.cpp
)

# Executable
add_executable(ConfigCollector ${SOURCES})

# Include directories
target_include_directories(ConfigCollector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty
)

# Link Qt libraries
target_link_libraries(ConfigCollector
    Qt6::Core
    Qt6::Network
)