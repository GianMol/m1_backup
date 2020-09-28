#include <iostream>
#include "FileWatcher.h"
#include <filesystem>

#include <boost/algorithm/string.hpp>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if(argc < 2){
        std::cerr << "Error: parameters missing";
        return -1;
    }
    fs::path folder = argv[1];

    /********************************************* fixing path in case of windows systems *************************************************************************/
    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__CYGWIN__)

        std::cout << "Running on Windows" << std::endl;
        std::string fol = folder.u8string();
        if (argv[1][1] == ':') { //if path is a windows absolute path
            std::string buf;
            buf.assign(1, tolower((argv[1][0])));
            std::string string = "/cygdrive/" + buf + folder.relative_path().u8string().substr(2);
            std::replace(string.begin(), string.end(), '\\', '/');
            folder = string;
        } else if (fol.find('\\') != std::string::npos) {  //else if path is a windows relative path
            std::replace(fol.begin(), fol.end(), '\\', '/');
            folder = fol;
        }
    #endif


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
