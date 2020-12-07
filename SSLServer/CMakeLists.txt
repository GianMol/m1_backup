cmake_minimum_required(VERSION 3.17)
project(SSLServer)
set(CMAKE_CXX_STANDARD 17)
add_executable(${PROJECT_NAME} main.cpp)

######################### OPENSSL ########################
find_package(OpenSSL REQUIRED)
set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} /usr/local/Cellar/openssl@1.1/1.1.1g/)
set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib CACHE FILEPATH "" FORCE)
set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.dylib CACHE FILEPATH "" FORCE)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto OpenSSL::SSL)

if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "Openssl not found!")
endif()

######################### BOOST #########################
set(BOOST_ROOT CACHE PATH /usr/local/Cellar/boost/1.73.0/)
find_package(Boost 1.73.0 REQUIRED COMPONENTS serialization system)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Could not find boost!")
endif()

