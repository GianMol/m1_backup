#include <iostream>
#include "FileWatcher.h"
#include <filesystem>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/string.hpp>
#include <string>

#include <boost/asio.hpp>
#include <openssl/evp.h>
#include <openssl/md5.h>

#define SIZE 1024

#if defined(_WIN32) //Windows 32
    #define SO "Windows"
#elif defined(_WIN64) //Windows 64
    #define SO "Windows"
#elif defined(__APPLE__) && defined(__MACH__) // Apple OSX and iOS (Darwin)
    #define SO "Apple"
#elif defined(__linux__) // Debian, Ubuntu, Gentoo, Fedora, openSUSE, RedHat, Centos and other
    #define SO "Linux"
#endif

struct Message
{
    std::string _a;
    std::string _b;

    template <class Archive>
    void serialize(
            Archive& ar,
            unsigned int version
    )
    {
        ar & _a;
        ar & _b;
    }
};

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    /*std::cout << SO << std::endl;
    EVP_MD_CTX *ctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char buf[SIZE] = {1,2,3,4,5,6,7,8,89,4,34,2,2,4,5,6,8,100};
    int len;
    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit(ctx, EVP_md5());
    EVP_DigestUpdate(ctx, buf, SIZE);
    EVP_DigestFinal_ex(ctx, md_value, reinterpret_cast<unsigned int *>(&len));
    std::cout << "hash: " << md_value << std::endl;
    EVP_MD_CTX_free(ctx);

    if(argc < 2){
        std::cerr << "Error: parameters missing";
        return -1;
    }
    fs::path folder = argv[1];
    std::string path = argv[1];
    std::cout << "Syncronizing folder: " << folder << std::endl;*/



    boost::asio::io_service io_service;

    // Client socket
    boost::asio::ip::tcp::socket client_socket(io_service);

    boost::system::error_code err;
    client_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"),9999), err);
    if(err.failed()) {
        std::cout << "Connessione non riuscita" << std::endl;
        return 0;
    }


    //write(client_socket, boost::asio::buffer(md_value));

    /*
    write(client_socket, boost::asio::buffer("person"));
    boost::asio::streambuf buffer;
    boost::asio::read_until(client_socket, buffer, "\n");
    write(client_socket, boost::asio::buffer("damiano"));
    boost::asio::read_until(client_socket, buffer, "\n");
    write(client_socket, boost::asio::buffer("zappulla"));
    boost::asio::read_until(client_socket, buffer, "\n");
     */

    /*
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
    });*/
}
