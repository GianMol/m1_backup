cmake_minimum_required(VERSION 3.17)
project(SerClient)

set(CMAKE_CXX_STANDARD 17)

set(BOOST_ROOT CACHE PATH /usr/local/Cellar/boost/1.73.0/)
find_package(Boost 1.73.0 COMPONENTS serialization system)

add_executable(${PROJECT_NAME} main.cpp)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME}
        ${Boost_LIBRARIES})

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Could not find boost!")
endif()

