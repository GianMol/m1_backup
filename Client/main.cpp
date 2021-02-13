#include "Functions.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if(argc < 3){
        std::cerr << "Error: parameters missing";
        return 0;
    }

    std::string id = argv[1];
    password = argv[2];
    std::string certificate;

    if(!load_certificate(certificate)){
        std::cerr << "Error: list of certificate files missing. Shutdowning..." << std::endl;
        return 0;
    }

    std::unique_lock<std::mutex> ul(m);
    boost::asio::io_context ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12);

    //Verification of server certificate
    ssl_ctx.load_verify_file(certificate);

    boost::asio::ip::tcp::resolver resolver(ctx);
    auto endpoint = resolver.resolve(SERVER, PORT);

    /*************************** Authentication Phase ***************************/
    struct request auth_pack;
    auth_pack.id = id;
    auth_pack.packet_type = auth_request;
    auth_pack.auth.password = password;

    if(auth(auth_pack, ctx, ssl_ctx, endpoint) != 1){
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }
    else{
        std::cout << "Authentication ok" << std::endl;
    }
    /************************ Authentication Phase Ended ************************/

    /****************** Fixing path in case of windows systems *****************/
    folder = translate_path_to_cyg(folder);

    if(!fs::is_directory(folder)){
        std::cerr << "Error: the argument is not a directory. Shutdowning..." << std::endl;
        return 0;
    }

    /********************************** Menu **********************************/
    std::string choice_string = "0";
    int choice;
    do {
        std::cout << std::endl << "********************** MENU **********************" << std::endl;
        std::cout
                << "1) Download backup from remote server." << std::endl
                << "2) Synchronize server from local folder." << std::endl
                << "3) Check the synchronization of some data."<< std::endl
                << "4) Exit." << std::endl;

        std::cin >> choice_string;

        //Fixing user input in case of unexpected or tainted data
        try{
            choice = boost::lexical_cast<int>(choice_string.at(0));
        }
        catch (boost::bad_lexical_cast const& err) {
            choice = 0;
        }

        switch(choice){
            case 1: {
                std::cout << "Downloading backup..." << std::endl;
                if (!down(id, ctx, ssl_ctx, endpoint)) {
                    std::cerr << "Error in downloading." << std::endl;
                    return 0;
                }
                std::cout << "Download succeded." << std::endl;
                choice = -1;
                break;
            }
            case 2: {
                std::cout << "Synchronizing folder..." << folder << std::endl;
                if (sync(folder, id, ctx, ssl_ctx, endpoint) != 1) {
                    std::cerr << "Error in synchronization." << std::endl;
                    return 0;
                }
                std::cout << "Synchronization succeded." << std::endl;
                choice = -1;
                break;
            }
            case 3: {
                std::cout << "Insert path to check: " << std::endl;
                std::string path;
                std::cin.ignore();
                std::getline(std::cin, path);
                int result = check(path, id, ctx, ssl_ctx, endpoint);
                if(result == 0){
                    std::cerr << "Impossible checking path" << std::endl;
                }
                else if(result == -1){
                    std::cout << "File is not synchronized" << std::endl;
                }
                else if(result == -2){
                    std::cout << "File does not exist" << std::endl;
                }
                else {
                    std::cout << "File synchronized" << std::endl;
                }
                break;
            }
            case 4: {
                std::cout << "Shutdowning..." << std::endl;
                return 0;
            }
            default:
                choice = 0;
                std::cout << "Insert a valid value." << std::endl;
        }
    }
    while(0 <= choice && choice < 4);
    /****************************** Menu End ******************************/

    /*********************** Monitoring Phase ****************************/

    //A secondary thread aims to monitor local changes
    std::thread thread(file_watcher);
    ThreadGuard t_guard(thread);

    //A shared pair queue, accessible through the use of a condition variable, is used to handle changes between the file watcher trhead and the main one,
    //Which is responsible of communicating with server
    while(true){
        cv.wait(ul, [](){return !queue.empty();});
        struct pair p = queue.front();
        queue.pop();
        cv.notify_all();

        std::cout << p.path << ", " << (p.status == FileStatus::created? "created" : (p.status == FileStatus::modified? "modified" : "erased")) << std::endl;
        fs::path path_relative = fs::relative(p.path, folder);

        //Send file
        if(!send_file(path_relative, id, ctx, ssl_ctx, endpoint, p.status == FileStatus::erased? operation::del : operation::create)){
            //Network error
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
