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

    std::unique_lock<std::mutex> ul(m);

    boost::asio::io_context ctx;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12);
    ssl_ctx.load_verify_file("/Users/damiano/Documents/Clion/CorradoServer/myCA.pem");
    boost::asio::ip::tcp::resolver resolver(ctx);
    auto endpoint = resolver.resolve(SERVER, PORT);


    /*********** authentication phase ***************************/

    struct packet auth_pack;
    auth_pack.id = id;
    auth_pack.packet_type = auth_request;
    auth_pack.auth.password = password;

    if(!auth(auth_pack, ctx, ssl_ctx, endpoint)){
        return -1;
    }

    /*********** authentication phase ended **********************/

    /*********** fixing path in case of windows systems **********/
    folder = translate_path_to_cyg(folder);

    /************ synchronization phase ***************************/
    if(!fs::is_directory(folder)){
        std::cerr << "Error: the argument is not a directory. Shutdowning..." << std::endl;
        return -1;
    }

    std::cout << "Syncronizing folder " << folder << std::endl;

    if(!sync(folder, id, ctx, ssl_ctx, endpoint)){
        std::cerr << "Error sync" << std::endl;
        return -1;
    }

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
            std::cout << "Error" << std::endl;
            return -1;
        }
    }
}
