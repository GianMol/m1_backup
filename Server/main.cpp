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
#include <cstdio>


namespace fs = std::filesystem;
#define SIZE 1024

//global variable socket
fs::path folder = "/cygdrive/c/Users/Corrado/Desktop/ex"; //it is a global variable in order to get the subdirectories and files relative path
std::string id ="10";

struct sync_protocol_response{
    std::string id;
    std::vector<fs::path> modified_paths;
};

enum operation { create, del, append, end };
enum type { directory, file, file_empty };

struct modify_request{
    std::string id;
    fs::path path;
    operation op;
    type type;
    std::string content;
};

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

int main() {
    /*
     * The server receive packets from the client. These could be synch or general packets.
     *
     * /
    /**************************SYNCH REQUEST****************************/
    std::map<fs::path, std::string> received_paths;
    std::map <fs::path, std::string> current_hashs;
    std::map <fs::path, std::string>::iterator it;
    struct sync_protocol_response res;
    std::string hash;
    //The server checks if this paths are beign modified or not. The modified one wll be inserted into a vector

    //Compute the hashs of all files and folders of server
    for(auto &file : fs::recursive_directory_iterator(folder)) {
        if(!compute_hash((fs::path &) file, hash)){
            std::cerr << "Error" << std::endl;
            return 0;
        }
        else {
            current_hashs.insert(std::pair<fs::path, std::string>(fs::relative(file, folder), hash));
        }
    }

    for (it=received_paths.begin();it!=received_paths.end();it++){
        auto position = current_hashs.find(it->first);
        if(position==current_hashs.end()){//Path non presente, bisogna inserirlo nel vettore
            res.modified_paths.push_back(it->first);
        }
        else{
            compute_hash((fs::path &) position->first,hash);
            if(hash!=it->second)//Hash diversi
                res.modified_paths.push_back(it->first);
        }
    }
    //Send_to_client(res)
    /*********************************Normal traffic**************************************/
    struct modify_request normal_traffic;
    fs::path ex = "/cygdrive/c/Users/Corrado/Desktop/ex/file.txt";
    normal_traffic.path=ex;
    normal_traffic.op=append;//Funziona con del, ma da errore
    normal_traffic.content="ciaociaociao\nciaociaociao\n";
    if(normal_traffic.op==create) {
        //Create a file in the directory
        std::ofstream fs(normal_traffic.path);
        if (!fs) {
            std::cerr << "Cannot open the output file." << std::endl;
            return 1;
        }
        fs << normal_traffic.content;
        fs.close();
    }
    else if (normal_traffic.op==del) {
        //Delete a file from the directory
        if (remove(normal_traffic.path) != 0)
            perror("File deletion failed");
        else
            std::cout << "File deleted successfully";
    }
    else if (normal_traffic.op==append) {
        //Append content to a file
        std::ofstream outfile;
        outfile.open(normal_traffic.path, std::ios_base::app);
        outfile << "Data to append";
    }


    //Il server riceve il pacchetto, e da questo costruisce la struct apposita
    //In base al contenuto del pacchetto esegue azioni diverse:
        //-Sincronizzazione: Creare funzione per sincronizzare, confrontare i path della cartella con quella ricevuta;
        //-Modifica: Creare, Eliminare o modificare il file

    // Create a FileWatcher instance that will check the current folder for changes every 5 seconds

    FileWatcher fw{folder, std::chrono::milliseconds(5000)};
    std::cout << "Syncronizing folder " << folder << std::endl;

    // Start monitoring a folder for changes and (in case of changes)
    // run a user provided lambda function
    fw.start([id](std::string path_to_watch, FileStatus status) -> void {
        // Process only regular files, all other file types are ignored
        if(!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
            return;
        }

        switch(status) {
            case FileStatus::created:
                std::cout << "File created: " << path_to_watch << std::endl;
                break;
            case FileStatus::modified:
                std::cout << "File modified: " << path_to_watch << std::endl;
                break;
            case FileStatus::erased:
                std::cout << "File deleted: " << path_to_watch << std::endl;
                break;
            default:
                std::cout << "Error! Unknown file status.\n";
        }
    });
}
