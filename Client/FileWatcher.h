#ifndef PROVA_PROGETTO_FILEWATCHER_H
#define PROVA_PROGETTO_FILEWATCHER_H

#pragma once
#include <filesystem>
#include <chrono>
#include <thread>
#include <unordered_map>
#include <string>
#include <functional>

namespace fs = std::filesystem;

enum class FileStatus {created, modified, erased};

class FileWatcher {
public:
    std::string path_to_watch;
    // Time interval at which we check the base folder for changes
    std::chrono::duration<int, std::milli> delay;

    // Keep a record of files from the base directory and their last modification time
    FileWatcher(std::string path_to_watch, std::chrono::duration<int, std::milli> delay);
    void start(const std::function<void (std::string&, FileStatus)> &action);
    std::unordered_map<std::string, fs::file_time_type> get_map();

private:
    std::unordered_map<std::string, fs::file_time_type> paths_;
    bool running_ = true;
    bool contains(const std::string &key);
};


#endif //PROVA_PROGETTO_FILEWATCHER_H