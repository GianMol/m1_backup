#include <iostream>
#include "FileWatcher.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <openssl/evp.h>
#include <string>


namespace fs = std::filesystem;
#define SIZE 1024

enum operation { create, del, append };
enum type { folder, file, file_empty };

struct protocol{
    fs::path path;
    operation op;
    type type;
    std::string content;
};

struct sync_protocol{
    std::map<fs::path, std::string> client_paths;
    std::vector<fs::path> modified_paths;
};

/***************** PROTOTYPES ***********************/
int send_file(fs::path& path, operation op = create);


std::string translate_path_to_cyg(fs::path& path){
    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__CYGWIN__)
        std::string fol = path.u8string();
        if (fol[1] == ':') { //if path is a windows absolute path
            std::string buf;
            buf.assign(1, tolower((fol[0])));
            std::string string = "/cygdrive/" + buf + path.u8string().substr(2);
            std::replace(string.begin(), string.end(), '\\', '/');
            return string;
        } else if (fol.find('\\') != std::string::npos) {  //else if path is a windows relative path
            std::replace(fol.begin(), fol.end(), '\\', '/');
            return fol;
        }
    #endif

    return path;
}

std::string translate_path_to_win(fs::path& path){
    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__CYGWIN__)
        std::string fol = path.u8string().substr(10);
        std::replace(fol.begin(), fol.end(), '/', '\\');
        if(fol.find('\\') == 1){    //absolute path
            std::string buf;
            buf.assign(1, toupper((fol[0])));
            std::string string = buf + ":\\" + fol.substr(2);
            return string;
        }
        else{
            return fol;
        }
    #endif

    return path;
}

int compute_hash(fs::path& path, std::string& hash){
    EVP_MD_CTX *ctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char buf[SIZE];
    int len;

    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit(ctx, EVP_md5());


    std::ifstream in;
    in.open(path, std::ios::binary);
    if(!in.is_open()){
        return 0;
    }

    while(!in.eof()) {
        in.read((char *) buf, SIZE);
        if (in.bad()) return 0;
        else{
            EVP_DigestUpdate(ctx, buf, SIZE);
        }
    }

    EVP_DigestFinal_ex(ctx, md_value, reinterpret_cast<unsigned int *>(&len));

    EVP_MD_CTX_free(ctx);
    hash = reinterpret_cast< char const* >(md_value);
    return 1;
}

int sync(fs::path& folder){


    std::map<fs::path, std::string> all_paths;

    for(auto &file : fs::recursive_directory_iterator(folder)) {
        if(fs::is_directory(file)){
            all_paths.insert(std::pair<fs::path, std::string>(file, "0"));
        }
        else{
            std::string hash;
            if(!compute_hash((fs::path &) file, hash)){
                std::cerr << "Error" << std::endl;
                return 0;
            }
            else {
                all_paths.insert(std::pair<fs::path, std::string>(file, hash));
            }
        }
    }
    struct sync_protocol packet;
    packet.client_paths = all_paths;


    for(auto& item : packet.client_paths){
        std::cout << "first: " << item.first << std::endl;
        std::cout << "second: " << item.second << std::endl;
    }


    /*
     *
     * send to server packet;
     * the server send to me the modified paths in a vector
     *
     * */
    std::cout << std::endl << "Sono il server. Mappa ricevuta: mando il vettore" << std::endl << std::endl;
    packet.modified_paths.emplace_back("/cygdrive/c/Users/gianl/Desktop/prova/Nuova cartella/documento.txt");
    packet.modified_paths.emplace_back("/cygdrive/c/Users/gianl/Desktop/prova/prova2.txt");
    for(auto &file : packet.modified_paths) {
        if(!send_file(file)){
            return 0;
        }
    }
    return 1;
}

int send_file(fs::path& path, operation op){
    std::cout << "leggendo il file: " << path << std::endl;
    if(fs::is_directory(path)){
        if(op == del){
            /*
             *
             * delete all subfiles and subdirectories
             * recursive call send_file();
             *
             * for(auto& file : fs::recursive_directory_iterator(path)){
             *      send_file(file, del);
             * }
             *
             *
             * then, send to server the information about the deletion of the folder
             *
             * */
            return 1;
        }
        /*
         * send path to server
         *
         * */
        return 1;
    }
    else if(op == del){
        /*
         *
         * send to server the information about the deletion of the file
         *
         *
         *
         * */
        return 1;
    }
    else {
        std::ifstream in;
        in.open(path, std::ios::binary);
        if (!in.is_open()) {
            return 0;
        }
        int i = 0;
        void *buf = (void *) malloc(SIZE);
        while (!in.eof()) {
            in.read((char *) buf, SIZE);
            if (in.bad()) return 0;

            /*  send to server
             *  if i == 0, then server will create a new file;
             *  else server will append the existing file;
             *  we send to the server 00 (create) for i == 0; 01 (append) for i != 0;
             *  in any case, in the message there will be the content of the file
             *
             *
             */
            //std::cout << (char*)buf << std::endl;
            std::cout << i << std::endl;
            i++;
        }
        in.close();
        free(buf);
        return 1;
    }
}





int main(int argc, char* argv[]) {
    if(argc < 2){
        std::cerr << "Error: parameters missing";
        return -1;
    }
    fs::path folder = argv[1];

    /********** fixing path in case of windows systems **********/
    folder = translate_path_to_cyg(folder);

    std::cout << "Syncronizing folder " << folder << std::endl;


    // Create a FileWatcher instance that will check the current folder for changes every 5 seconds
    FileWatcher fw{folder, std::chrono::milliseconds(5000)};

    if(!sync(folder)){
        std::cerr << "Error sync" << std::endl;
        return -1;
    }








    // Start monitoring a folder for changes and (in case of changes)
    // run a user provided lambda function
    fw.start([folder] (std::string path_to_watch, FileStatus status) -> void {
        // Process only regular files, all other file types are ignored
        if(!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
            return;
        }

        switch(status) {
            case FileStatus::created:
                std::cout << "File created: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                break;
            case FileStatus::modified:
                std::cout << "File modified: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                break;
            case FileStatus::erased:
                std::cout << "File erased: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                break;
            default:
                std::cout << "Error! Unknown file status.\n";
        }
    });

}
