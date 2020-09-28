#include <iostream>
#include <boost/asio.hpp>
#include <filesystem>

#if defined(_WIN32) //Windows 32
    #define SO "Windows"
#elif defined(_WIN64) //Windows 64
    #define SO "Windows"
#elif defined(__APPLE__) && defined(__MACH__) // Apple OSX and iOS (Darwin)
    #define SO "Apple"
#elif defined(__linux__) // Debian, Ubuntu, Gentoo, Fedora, openSUSE, RedHat, Centos and other
#endif

int main() {
    std::cout << SO << std::endl;
    return 0;
}
