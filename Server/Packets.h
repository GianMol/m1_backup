/************ STL ************/
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <iomanip>
#include <sstream>

/*********** BOOST ***********/
#include <boost/asio.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

/********** OPENSSL **********/
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>

/*********** MYLIB ***********/
#include "FileWatcher.h"
#include "ThreadGuardVector.cpp"
#include <sqlite3.h>

namespace fs = std::filesystem;

enum operation {create, del};
enum type {modify_request, sync_request, sync_response, auth_request, response, down_request, down_response, file_request, file_response};

struct auth_request{
    std::string password;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & password;
    }
};

struct general_response{
    bool res;
    std::string description;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & res;
        ar & description;
    }
};

struct modify_request{
    std::string path;
    operation op;
    std::string content;
    std::string permissions;
    bool is_directory;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & path;
        ar & op;
        ar & content;
        ar & permissions;
        ar & is_directory;
    }
};

struct sync_request{
    std::map<std::string, std::string> client_paths;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & client_paths;
    }
};

struct sync_response{
    std::vector<std::string> modified_paths;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & modified_paths;
    }
};

struct down_response{
    std::map<std::string, std::string> server_paths;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & server_paths;
    }
};

struct file_request{
    std::string path;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & path;
    }
};

struct file_response{
    std::string path;
    std::string content;
    std::string permissions;
    bool is_directory;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & path;
        ar & content;
        ar & permissions;
        ar & is_directory;
    }
};

struct request{
    std::string id;
    type packet_type;
    std::string token;
    struct auth_request auth;
    struct modify_request mod;
    struct sync_request sync_req;
    struct file_request file_req;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & id;
        ar & packet_type;
        ar & token;
        ar & auth;
        ar & mod;
        ar & sync_req;
        ar & file_req;
    }
};

struct response{
    std::string id;
    type packet_type;
    std::string token;
    struct general_response gen_res;
    struct sync_response sync_res;
    struct down_response down_res;
    struct file_response file_res;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & id;
        ar & packet_type;
        ar & token;
        ar & gen_res;
        ar & sync_res;
        ar & down_res;
        ar & file_res;
    }
};

struct pair{
    fs::path path;
    FileStatus status;
};