#include <iostream>
#include "FileWatcher.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <openssl/evp.h>
#include <string>
#include <future>


namespace fs = std::filesystem;
#define SIZE 1024

//global variable socket
fs::path folder; //it is a global variable in order to get the subdirectories and files relative path

enum operation { create, del, append, end };
enum type { directory, file, file_empty };

struct modify_request{
    std::string id;
    fs::path path;
    operation op;
    type type;
    std::string content;
};

struct modify_response{
    std::string id;
    int res;
    std::string description;
};

struct sync_protocol_request{
    std::string id;
    std::map<fs::path, std::string> client_paths;
};

struct sync_protocol_response{
    std::string id;
    std::vector<fs::path> modified_paths;
};

/***************** PROTOTYPES ***********************/
int send_file(fs::path& path, std::string& id, operation op = create);


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

int sync(fs::path& directory, std::string& id){
    std::map<fs::path, std::string> all_paths;

    if(!fs::is_directory(directory)){
        std::cerr << "Error: it is not a directory." << std::endl;
        return 0;
    }
    for(auto &file : fs::recursive_directory_iterator(directory)) {
        if(fs::is_directory(file)){
            all_paths.insert(std::pair<fs::path, std::string>(fs::relative(file, directory), "0"));
        }
        else{
            std::string hash;
            if(!compute_hash((fs::path &) file, hash)){
                std::cerr << "Error" << std::endl;
                return 0;
            }
            else {
                all_paths.insert(std::pair<fs::path, std::string>(fs::relative(file, directory), hash));
            }
        }
    }
    struct sync_protocol_request packet;
    packet.client_paths = all_paths;
    packet.id = id;


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
    struct sync_protocol_response response;

    /************************************************ Server emulation *****************************************************************************/
    std::cout << std::endl << "Sono il server. Mappa ricevuta: mando il vettore" << std::endl << std::endl;
    response.modified_paths.emplace_back("/cygdrive/c/Users/gianl/Desktop/prova/Nuova cartella/documento.txt");
    response.modified_paths.emplace_back("/cygdrive/c/Users/gianl/Desktop/prova/prova2.txt");
    response.id = id;


    if(response.id != id){
        std::cerr << "Error " << std::endl;
        return 0;
    }
    for(auto &file : response.modified_paths) {
        if(!send_file(file, id)){
            return 0;
        }
        //std::async();
    }

    std::cout << "synchronization succeded" << std::endl;
    return 1;
}

struct modify_request create_modify_request(std::string& id, fs::path& path, enum operation op, int i, enum type t, void* buf){
    struct modify_request pack;
    pack.id = id;
    std::string p = path;   //we convert std::filesystem::path to a std::string to void problems like file names with spaces
    pack.path = fs::relative(p, folder);
    pack.op = op;
    pack.type = t;
    if(buf) pack.content = reinterpret_cast<char*>(buf);
    return pack;
}

int send_file(fs::path& path, std::string& id, operation op){
    //std::cout << "leggendo il file: " << path << std::endl;
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
            for(auto& file : fs::directory_iterator(path)){
                if(!send_file((fs::path&)file, id, del)) return 0;
            }
            std::cout << "delete directory: " << path << std::endl;

            struct modify_request pack = create_modify_request(id, path, del, 0, directory, nullptr);
            std::cout << "path: " << pack.path << " " << "op: " << pack.op << std::endl;

            //send to server
            return 1;
        }
        else {
            /*
             * send path to server
             *
             * */
            struct modify_request pack = create_modify_request(id, path, create, 0, directory, nullptr);
            std::cout << "path: " << pack.path << " " << "op: " << pack.op << std::endl;

            //send to server

            return 1;
        }
    }
    else if(op == del){
        /*
         *
         * send to server the information about the deletion of the file
         *
         *
         *
         * */


        struct modify_request pack = create_modify_request(id, path, del, 0, file, nullptr);
        std::cout << "path: " << pack.path << " " << "op: " << pack.op << std::endl;

        //send to server

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
             *  we send to the server create for i == 0; append for i != 0; then, we send an end message
             *  in any case, in the message there will be the content of the file
             *
             *
             */
            struct modify_request pack = create_modify_request(id, path, i==0? create : append, i, file, buf);


            //send pack to server

            std::cout << "path: " << pack.path << " " << "op: " << pack.op << std::endl;
            i++;
        }
        struct modify_request pack = create_modify_request(id, path, end, 0, file, nullptr);

        // send pack to server

        std::cout << "path: " << pack.path << " " << "op: " << pack.op << std::endl;

        in.close();
        free(buf);
        return 1;
    }
}




int main(int argc, char* argv[]) {
    if(argc < 4){
        std::cerr << "Error: parameters missing";
        return -1;
    }
    folder = argv[1];
    std::string id = argv[2];
    std::string password = argv[3];

    //socket variable init

    /********** fixing path in case of windows systems **********/
    folder = translate_path_to_cyg(folder);

    if(!fs::is_directory(folder)){
        std::cerr << "Error: the argument is not a directory. Shutdowning..." << std::endl;
        return -1;
    }

    std::cout << "Syncronizing folder " << folder << std::endl;


    // Create a FileWatcher instance that will check the current folder for changes every 5 seconds
    FileWatcher fw{folder, std::chrono::milliseconds(5000)};


    if(!sync(folder, id)){
        std::cerr << "Error sync" << std::endl;
        //free socket
        return -1;
    }

    //fs::path p = "/cygdrive/c/Users/gianl/Desktop/prova/Nuova cartella/pr.txt";
    //if(!send_file(p, (std::string&)id, del)) std::cout << p << std::endl;





    // Start monitoring a folder for changes and (in case of changes)
    // run a user provided lambda function
    fw.start([id] (std::string path_to_watch, FileStatus status) -> void {
        // Process only regular files, all other file types are ignored
        if(!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
            return;
        }

        switch(status) {
            case FileStatus::created:
                //call send_file();
                std::cout << "File created: " << std::endl;
                if(!send_file((fs::path&)path_to_watch, (std::string&)id)) return;
                //std::cout << "File created: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                //std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                // if error free socket and close process
                // else, async
                break;
            case FileStatus::modified:
                std::cout << "File modified: " << std::endl;
                //call send_file();
                if(!send_file((fs::path&)path_to_watch, (std::string&)id)) return;
                //std::cout << "File modified: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                //std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                // if error free socket and close process
                // else, async
                break;
            case FileStatus::erased:
                std::cout << "File deleted: " << std::endl;
                if(!send_file((fs::path&)path_to_watch, (std::string&)id, del)) return;
                //call send_file();
                //std::cout << "File erased: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                //std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                // if error free socket and close process
                // else, async
                break;
            default:
                std::cout << "Error! Unknown file status.\n";
        }
    });

}
