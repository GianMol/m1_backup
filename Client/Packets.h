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

/*********** BOOST ***********/
#include <boost/asio.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>

/********** OPENSSL **********/
#include <openssl/evp.h>
#include <openssl/sha.h>

/*********** MYLIB ***********/
#include "FileWatcher.h"

namespace fs = std::filesystem;

enum operation {create, del, append, end};
enum type {modify_request, sync_request, sync_single_file_request, sync_response, auth_request, response};

struct auth_request{
    std::string password;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & password;
    }
};

struct response{
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

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & path;
        ar & op;
        ar & content;
        ar & permissions;
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
    std::string description;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & modified_paths;
        ar & description;
    }
};

struct packet{
    std::string id;
    type packet_type;
    struct auth_request auth;
    struct modify_request mod;
    struct response res;
    struct sync_request sync_req;
    struct sync_response sync_res;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & id;
        ar & packet_type;
        ar & auth;
        ar & mod;
        ar & res;
        ar & sync_req;
        ar & sync_res;
    }
};

struct pair{
    fs::path path;
    FileStatus status;
};