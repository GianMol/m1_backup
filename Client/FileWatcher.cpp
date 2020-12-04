#include "FileWatcher.h"
#include <filesystem>
#include <boost/asio.hpp>

namespace fs = std::filesystem;

FileWatcher::FileWatcher(std::string path_to_watch, std::chrono::duration<int, std::milli> delay) : path_to_watch{path_to_watch}, delay{delay} {
    for(auto &file : fs::recursive_directory_iterator(path_to_watch)) {
        paths_[file.path().string()] = fs::last_write_time(file);
    }
}

bool FileWatcher:: contains(const std::string &key) {
    auto el = paths_.find(key);
    return el != paths_.end();
}

void FileWatcher:: start(const std::function<void (std::string, FileStatus)> &action) {
    while(running_) {
        // Wait for "delay" milliseconds
        std::this_thread::sleep_for(delay);

        auto it = paths_.begin();
        while (it != paths_.end()) {
            if (!fs::exists(it->first)) {
                action(it->first, FileStatus::erased);
                it = paths_.erase(it);
            }
            else {
                it++;
            }
        }

        // Check if a file was created or modified
        for(auto &file : fs::recursive_directory_iterator(path_to_watch)) {
            auto current_file_last_write_time = fs::last_write_time(file);
            // File creation
            if(!contains(file.path().string())) {
                paths_[file.path().string()] = current_file_last_write_time;
                action(file.path().string(), FileStatus::created);
                // File modification
            } else {
                if(paths_[file.path().string()] != current_file_last_write_time) {
                    paths_[file.path().string()] = current_file_last_write_time;
                    action(file.path().string(), FileStatus::modified);
                }
            }
        }
    }
}

std::unordered_map<std::string, fs::file_time_type> FileWatcher::get_map(){
    return this->paths_;
}