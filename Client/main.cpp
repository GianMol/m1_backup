#include <iostream>
#include "FileWatcher.h"
#include <filesystem>
#include <boost/thread.hpp>

#if defined(_WIN32) //Windows 32
    #define SO "Windows"
#elif defined(_WIN64) //Windows 64
    #define SO "Windows"
#elif defined(__APPLE__) && defined(__MACH__) // Apple OSX and iOS (Darwin)
    #define SO "Apple"
#elif defined(__linux__) // Debian, Ubuntu, Gentoo, Fedora, openSUSE, RedHat, Centos and other
    #define SO "Linux"
#endif

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    std::cout << SO << std::endl;
    if(argc < 2){
        std::cerr << "Error: parameters missing";
        return -1;
    }
    fs::path folder = argv[1];
    std::cout << "Syncronizing folder " << folder << std::endl;




    // Create a FileWatcher instance that will check the current folder for changes every 5 seconds
    FileWatcher fw{argv[1], std::chrono::milliseconds(5000)};

    // Start monitoring a folder for changes and (in case of changes)
    // run a user provided lambda function
    fw.start([folder] (std::string path_to_watch, FileStatus status) -> void {
        // Process only regular files, all other file types are ignored
        if(!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
            return;
        }

        switch(status) {
            case FileStatus::created:
                std::cout << "File created: " << path_to_watch << std::endl;
                std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                break;
            case FileStatus::modified:
                std::cout << "File modified: " << path_to_watch << std::endl;
                std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                break;
            case FileStatus::erased:
                std::cout << "File erased: " << path_to_watch << std::endl;
                std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                break;
            default:
                std::cout << "Error! Unknown file status.\n";
        }
    });
}
