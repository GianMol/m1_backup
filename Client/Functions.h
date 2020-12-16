/*********** MYLIB é**********/
#include "Packets.h"
#include "SocketGuard.cpp"
#include "ThreadGuard.cpp"

#define SIZE 1024
#define SERVER "127.0.0.1"
#define PORT "9999"

namespace fs = std::filesystem;

/****** Global Variables ******/
fs::path folder; //it is a global variable in order to get the subdirectories and files relative path
std::queue<struct pair> queue;
std::mutex m;
std::condition_variable cv;

/***************** PROTOTYPES ***********************/
std::string translate_path_to_cyg(fs::path& path);
std::string translate_path_to_win(fs::path& path);
std::string translate_perms_to_string(fs::perms& p);
fs::perms translate_string_to_perms(std::string& string);
int compute_hash(fs::path& path, std::string& hash);
int sync(fs::path& directory, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);
struct packet create_modify_request(std::string& id, fs::path& path, enum operation op,  fs::file_status& status, std::string& buf);
int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint, operation op = create);
int send(struct packet & pack, socket_guard &socket);
int receive(struct packet & pack, socket_guard &socket);
void file_watcher();
int auth(struct packet& auth_pack, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);
int process_response(struct packet& pack);

/******************** FUNCTIONS *****************************/
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

std::string translate_perms_to_string(fs::perms& p){
    const fs::perms permissions[9] = {fs::perms::owner_read, fs::perms::owner_write, fs::perms::owner_exec,
                                fs::perms::group_read, fs::perms::group_write, fs::perms::group_exec,
                                fs::perms::others_read, fs::perms::others_write, fs::perms::others_exec};

    const std::string types[3] = {"r", "w", "x"};

    std::string res = ((p & permissions[0]) != fs::perms::none ? types[0] : "-");

    for(int i = 1; i < 9; i++){
        res += ((p & permissions[i]) != fs::perms::none ? types[i%3] : "-");
    }
    return res;
}

fs::perms translate_string_to_perms(std::string& string){
    const fs::perms permissions[9] = {fs::perms::owner_read, fs::perms::owner_write, fs::perms::owner_exec,
                                fs::perms::group_read, fs::perms::group_write, fs::perms::group_exec,
                                fs::perms::others_read, fs::perms::others_write, fs::perms::others_exec};
    fs::perms p = fs::perms::none;
    int i = 0;
    for(i=0; i < 9; i++){
        if(string[i] != '-') p |= permissions[i];
    }
    return p;
}

int compute_hash(fs::path& path, std::string& hash){

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char md_value[SHA256_DIGEST_LENGTH];
    unsigned char buf[SIZE];
    int len;

    std::ifstream in;
    in.open(path, std::ios::binary);
    if(!in.is_open()){
        return 0;
    }

    while(!in.eof()) {
        in.read((char *) buf, SIZE);
        if (in.bad()) return 0;
        else{
            SHA256_Update(&ctx, buf, SIZE);
        }
    }

    SHA256_Final(md_value, &ctx);

    hash = reinterpret_cast< char const* >(md_value);
    return 1;

    /*
    EVP_MD_CTX *ctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char buf[SIZE];
    int len;

    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit(ctx, EVP_sha256());

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
    */
}

int sync(fs::path& directory, std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint){
    std::map<std::string, std::string> all_paths;
    boost::system::error_code err;
    socket_guard socket(ctx, ssl_ctx);

    if(!fs::is_directory(directory)){
        std::cerr << "Error: it is not a directory." << std::endl;
        return 0;
    }

    for(auto &file : fs::recursive_directory_iterator(directory)) {
        std::string str_folder = (fs::path)file;
        int pos = str_folder.find_last_of('/');
        std::string str_file = str_folder.substr(pos, str_folder.length());
        if(str_file.at(1) != '.' || str_file.at(1) == '~'){
            std::string pr = (fs::path) file;
            if(fs::is_directory(file)){
                std::pair<std::string, std::string> pair = std::make_pair(fs::relative(file, directory), "\0");
                all_paths.insert(pair);
            }
            else {
                std::string hash;
                if(!compute_hash((fs::path &) file, hash)){
                    std::cerr << "Error in computing hash." << std::endl;
                    return 0;
                }
                else {
                    all_paths.insert(std::pair<std::string, std::string>(fs::relative(file, directory), hash));
                }
            }
        }
    }

    boost::asio::connect(socket.socket.lowest_layer(), endpoint, err);

    if (err) {
        std::cout << "Connection failed: " << err.message() << std::endl;
        return 0;
    }
    socket.socket.handshake(boost::asio::ssl::stream_base::client, err);
    if(err){
        std::cout << "Handshake failed: " << err.message() << std::endl;
        return 0;
    }

    struct packet pack;
    pack.packet_type = sync_request;
    pack.id = id;
    pack.sync_req.client_paths = all_paths;

    if(!send(pack, socket)){
        std::cerr << "Connection error: impossible sending sync packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }

    struct packet response;
    if(!receive(response, socket)){
        std::cerr << "Connection error: impossible receiving sync packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }

    socket.socket.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
    socket.socket.lowest_layer().close();

    /*if(response.id != id){
        std::cerr << "Error." << std::endl;
        return 0;
    }*/

    if(!response.sync_res.res){
        std::cerr << "Error: " << response.sync_res.description << std::endl;
        return 0;
    }

    for(auto &file : response.sync_res.modified_paths) {
        fs::path f = folder.string() + "/" + file;
        if(!send_file(f, id, ctx, ssl_ctx, endpoint)){
            std::cerr << "Impossible sending file during synchronization phase" << std::endl;
            return 0;
        }
    }

    std::cout << "Synchronization succeded." << std::endl;
    return 1;
}

struct packet create_modify_request(std::string& id, fs::path& path, enum operation op, fs::file_status& status, std::string& buf){
    struct packet pack;
    pack.packet_type = modify_request;
    pack.id = id;
    std::string p = path;   //we convert std::filesystem::path to a std::string to void problems like file names with spaces
    pack.mod.path = fs::relative(p, folder);
    pack.mod.op = op;
    pack.mod.is_directory = path.string().at(path.string().length() - 1) == '/' ? true : false;

    //convert fs::permissions to std::string
    fs::perms perms = status.permissions();
    std::string permissions = translate_perms_to_string(perms);
    pack.mod.permissions = permissions;
    pack.mod.content = buf;
    return pack;
}

int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint, operation op){
    std::string str_folder = path;
    int pos = str_folder.find_last_of('/');
    std::string str_file = str_folder.substr(pos, str_folder.length());
    if(str_file.at(1) == '.' || str_file.at(1) == '~') {
        return 1;
    }

    std::cout << path << std::endl;

    socket_guard socket(ctx, ssl_ctx);
    boost::system::error_code err;
    boost::asio::connect(socket.socket.lowest_layer(), endpoint, err);

    if (err) {
        std::cout << "Connection failed: " << err.message() << std::endl;
        return 0;
    }
    socket.socket.handshake(boost::asio::ssl::stream_base::client, err);
    if(err){
        std::cout << "Handshake failed: " << err.message() << std::endl;
        return 0;
    }

    if(fs::is_directory(path)){
        if(op == del){
            for(auto& file : fs::directory_iterator(path)){
                if(!send_file((fs::path&)file, id, ctx, ssl_ctx, endpoint, del)) return 0;
            }
            std::cout << "delete directory: " << path << std::endl;

            fs::file_status status = fs::status(path);
            struct packet pack = create_modify_request(id, path, del, status, (std::string&)"\0");

            //send to server
            if(!send(pack, socket)){
                std::cerr << "Connection error: impossible sending modify packets." << std::endl;
                std::cerr << "Shutdowning..." << std::endl;
                return 0;
            }

            struct packet res;
            if(!receive(res, socket)) {
                std::cerr << "Receiving error." << std::endl;
                return 0;
            }
            return process_response(res);
        }
        else {
            // send path to server
            fs::file_status status = fs::status(path);
            path += "/";
            struct packet pack = create_modify_request(id, path, create, status, (std::string&)"\0");

            //send to server
            if(!send(pack, socket)){
                std::cerr << "Connection error: impossible sending modify packets." << std::endl;
                std::cerr << "Shutdowning..." << std::endl;
                return 0;
            }

            struct packet res;
            if(!receive(res, socket)) {
                std::cerr << "Receiving error." << std::endl;
                return 0;
            }
            return process_response(res);
        }
    }
    else if(op == del){
        // send to server the information about the deletion of the file

        fs::file_status status = fs::status(path);
        struct packet pack = create_modify_request(id, path, del, status, (std::string&)"\0");
        std::cout << "path: " << pack.mod.path << " " << "op: " << pack.mod.op << std::endl;

        //send to server
        if(!send(pack, socket)){
            std::cerr << "Connection error: impossible sending modify packets." << std::endl;
            std::cerr << "Shutdowning..." << std::endl;
            return 0;
        }

        struct packet res;
        if(!receive(res, socket)) {
            std::cerr << "Receiving error." << std::endl;
            return 0;
        }
        return process_response(res);
    }
    else {
        std::ifstream in;
        in.open(path, std::ios::binary);
        if (!in.is_open()) {
            return 0;
        }
        std::streambuf *buf;
        buf = in.rdbuf();

        if (in.bad())
            return 0;

        std::string content((std::istreambuf_iterator<char>(buf)), std::istreambuf_iterator<char>());
        fs::file_status status = fs::status(path);
        struct packet pack = create_modify_request(id, path, create, status, content);

        if(!send(pack, socket)){
            std::cerr << "Connection error: impossible sending modify packets." << std::endl;
            std::cerr << "Shutdowning..." << std::endl;
            return 0;
        }

        in.close();

        struct packet res;
        if(!receive(res, socket)) {
            std::cerr << "Receiving error." << std::endl;
            return 0;
        }
        return process_response(res);
    }
}

int send(struct packet & pack, socket_guard &socket){
    //preparing the archive to send
    boost::asio::streambuf buf;
    std::ostream os(&buf);
    boost::archive::text_oarchive ar(os);
    ar & pack;
    boost::system::error_code err;

    const size_t header = buf.size();

    // send header and buffer using scatter
    std::vector<boost::asio::const_buffer> buffers;
    buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
    buffers.push_back(buf.data());

    const size_t rc = boost::asio::write(socket.socket, buffers, err);
    if (err) {
        std::cout << "Send failed: " << err.message() << std::endl;
        return 0;
    }
    std::cout << "Packet sent." << std::endl;

    return rc;
}

int receive(struct packet & pack, socket_guard &socket){
    size_t header;

    boost::system::error_code err;

    boost::asio::read(socket.socket, boost::asio::buffer(&header, sizeof(header)), err);

    if (err) {
        std::cout << "Receive failed." << std::endl;
        return 0;
    }

    // read body
    boost::asio::streambuf buf;
    const size_t rc = boost::asio::read(socket.socket, buf.prepare(header), err);

    if (err) {
        std::cout << "Receive failed." << std::endl;
        return 0;
    }

    std::cout << "Packet received." << std::endl;

    buf.commit(header);

    // deserialize
    std::istream is(&buf);
    boost::archive::text_iarchive ar(is);
    ar & pack;

    return rc;
}

void file_watcher(){
    FileWatcher fw{folder, std::chrono::milliseconds(5000)};

    fw.start([] (std::string path_to_watch, FileStatus status) -> void {

        if(!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
            return;
        }

        struct pair p;
        p.path = path_to_watch;
        std::unique_lock<std::mutex> ul(m);

        switch(status) {
            case FileStatus::created:

                std::cout << "File created: " << std::endl;

                p.status = FileStatus::created;
                queue.push(p);
                cv.notify_all();



                //if(!send_file((fs::path&)path_to_watch, (std::string&)id)) return;
                //std::cout << "File created: " << translate_path_to_win((fs::path&)path_to_watch) << std::endl;
                //std::cout << "path relativo " << fs::relative(path_to_watch, folder) << std::endl;
                // if error free socket and close process
                // else, async
                break;
            case FileStatus::modified:
                std::cout << "File modified: " << std::endl;

                p.status = FileStatus::modified;
                queue.push(p);
                cv.notify_all();

                break;
            case FileStatus::erased:
                std::cout << "File deleted: " << std::endl;

                p.status = FileStatus::erased;
                queue.push(p);
                cv.notify_all();

                break;
            default:
                std::cout << "Error! Unknown file status.\n";
        }
    });
}

int auth(struct packet& auth_pack, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint){
    socket_guard auth_socket(ctx, ssl_ctx);
    boost::system::error_code err;

    boost::asio::connect(auth_socket.socket.lowest_layer(), endpoint, err);

    if (err) {
        std::cout << "Auth connection failed: " << err.message() << std::endl;
        return 0;
    }
    auth_socket.socket.handshake(boost::asio::ssl::stream_base::client, err);
    if(err){
        std::cout << "Auth handshake failed: " << err.message() << std::endl;
        return 0;
    }

    //send auth_pack to server
    if(!send(auth_pack, auth_socket)){
        std::cerr << "Connection error: impossible sending authentication packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }

    //receive response from server
    struct packet auth_res;

    if(!receive(auth_res, auth_socket)){
        std::cerr << "Connection error: impossible receiving authentication packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }

    return process_response(auth_res);
}

int process_response(struct packet& pack){
    std::cout << pack.res.description << std::endl;
    return pack.res.res;
}