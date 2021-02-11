#include "Functions.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if(argc < 3){
        std::cerr << "Error: parameters missing";
        return -1;
    }

    std::string id = argv[1];
    std::string password = argv[2];
    std::string certificate;
    if(!load_certificate(certificate)){
        std::cerr << "Error: list of certificate files missing. Shutdowning..." << std::endl;
        return 0;
    }

    std::unique_lock<std::mutex> ul(m);

    boost::asio::io_context ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12);
    ssl_ctx.load_verify_file(certificate);
    boost::asio::ip::tcp::resolver resolver(ctx);
    auto endpoint = resolver.resolve(SERVER, PORT);


    /*********** authentication phase ***************************/

    struct request auth_pack;
    auth_pack.id = id;
    auth_pack.packet_type = auth_request;
    auth_pack.auth.password = password;

    if(!auth(auth_pack, ctx, ssl_ctx, endpoint)){
        return -1;
    }

    /*********** authentication phase ended **********************/

    /*********** fixing path in case of windows systems **********/
    folder = translate_path_to_cyg(folder);

    if(!fs::is_directory(folder)){
        std::cerr << "Error: the argument is not a directory. Shutdowning..." << std::endl;
        return -1;
    }
    /************ synchronization phase ***************************/

    int choice = 0;
    do {
        std::cout << "********************** MENÙ **********************" << std::endl;
        std::cout
        << "1) Download backup from remote server." << std::endl
        << "2) Synchronize server from local folder." << std::endl
        << "3) Check the synchronization of some data."<< std::endl
        << "4) Exit." << std::endl;
        std::cin >> choice;
        switch(choice){
            case 1: {
                std::cout << "Downloading backup..." << std::endl;
                if (!down(id, ctx, ssl_ctx, endpoint)) {
                    std::cerr << "Error in synchronization." << std::endl;
                    return -1;
                }
                std::cout << "Download succeded." << std::endl;
                choice = -1;
                break;
            }
            case 2: {
                std::cout << "Synchronizing folder..." << folder << std::endl;
                if (!sync(folder, id, ctx, ssl_ctx, endpoint)) {
                    std::cerr << "Error in synchronization." << std::endl;
                    return -1;
                }
                std::cout << "Synchronization succeded." << std::endl;
                choice = -1;
                break;
            }
            case 3: {
                std::cout << "Insert path to check: " << std::endl;
                std::string path;
                std::cin >> path;
                int result = check(path, id, ctx, ssl_ctx, endpoint);
                if(result == 0){
                    std::cerr << "Impossible checking path" << std::endl;
                    std::cerr << "Shutdowning..." << std::endl;
                    return 0;
                }
                else if(result == -1){
                    std::cout << "File is not synchronized" << std::endl;
                }
                else {
                    std::cout << "File is synchronized" << std::endl;
                }
                break;
            }
            case 4: {
                std::cout << "Shutdowning..." << std::endl;
                return 0;
            }
            default:
                std::cout << "Insert a valid value." << std::endl;
        }
    }
    while(0 <= choice && choice < 4);


    /************ synchronization phase ended *********************/

    /******************* monitoring phase *************************/
    std::thread thread(file_watcher);
    ThreadGuard t_guard(thread);

    while(true){
        cv.wait(ul, [](){return !queue.empty();});
        struct pair p = queue.front();
        queue.pop();
        cv.notify_all();

        std::cout << p.path << ", " << (p.status == FileStatus::created? "created" : (p.status == FileStatus::modified? "modified" : "erased")) << std::endl;

        //send file
        if(!send_file(p.path, id, ctx, ssl_ctx, endpoint, p.status == FileStatus::erased? operation::del : operation::create)){
            //here goes network error
            std::cerr << "Error: Impossible sending " + p.path.string() << std::endl;
        }
        else{
            auto it = std::find(invalid.begin(), invalid.end(), p.path);
            if(it != invalid.end()){
                invalid.erase(it);
            }
        }
    }
}
