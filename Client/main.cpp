#include "Functions.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if(argc < 4){
        std::cerr << "Error: parameters missing";
        return -1;
    }

    folder = argv[1];
    std::string id = argv[2];
    std::string password = argv[3];

    std::cout << folder << " " << id << " " << password << std::endl;

    std::unique_lock<std::mutex> ul(m);

    boost::asio::io_context ctx;
    socket_guard auth_socket(ctx);

    /******************* authentication phase *************************/
    struct packet auth_pack;
    auth_pack.id = id;
    auth_pack.packet_type = auth_request;
    auth_pack.auth.password = password;

    //send auth_pack to server
    if(!send(auth_pack, auth_socket)){
        std::cerr << "Connection error: impossible to send authentication packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return -1;
    }

    //receive response from server
    struct packet auth_res;

    if(!receive(auth_res, auth_socket)){
        std::cerr << "Connection error: impossible to receive authentication packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return -1;
    }

    if(!auth_res.res.res){
        std::cerr << "Authentication error." << std::endl;
        std::cerr << auth_res.res.description << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return -1;
    }

    /*********** fixing path in case of windows systems **********/
    folder = translate_path_to_cyg(folder);

    /******************* synchronization phase *************************/
    if(!fs::is_directory(folder)){
        std::cerr << "Error: the argument is not a directory. Shutdowning..." << std::endl;
        return -1;
    }

    std::cout << "Syncronizing folder " << folder << std::endl;

    if(!sync(folder, id, ctx)){
        std::cerr << "Error sync" << std::endl;
        return -1;
    }

    /******************* monitoring phase *************************/
    std::thread thread(file_watcher);
    ThreadGuard t_guard(thread);

    while(true){
        cv.wait(ul, [](){return !queue.empty();});
        struct pair p = queue.front();
        queue.pop();
        cv.notify_all();

        std::cout << p.path << ", " << (p.status == FileStatus::created? "created" : (p.status == FileStatus::modified? "modified" : "erased")) << std::endl;

        //inviare i pacchetti con send_file();
    }
}
