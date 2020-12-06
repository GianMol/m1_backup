/*********** MYLIB é**********/
#include "Packets.h"
#include "SocketGuard.cpp"
#include "ThreadGuard.cpp"

#define SIZE 1024
#define SERVER "127.0.0.1"

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
int sync(fs::path& directory, std::string& id, boost::asio::io_context & ctx);
struct packet create_modify_request(std::string& id, fs::path& path, enum operation op,  fs::file_status& status, void* buf);
int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, operation op = create);
int send(struct packet & pack, socket_guard &socket);
int receive(struct packet & pack, socket_guard &socket);
void file_watcher();

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

int sync(fs::path& directory, std::string& id, boost::asio::io_context& ctx){
    socket_guard socket(ctx);
    std::map<std::string, std::string> all_paths;

    if(!fs::is_directory(directory)){
        std::cerr << "Error: it is not a directory." << std::endl;
        return 0;
    }

    for(auto &file : fs::recursive_directory_iterator(directory)) {
        if(fs::is_directory(file)){
            all_paths.insert(std::pair<fs::path, std::string>(fs::relative(file, directory), "0"));
        }
        else {
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

    struct packet pack;
    pack.packet_type = sync_request;
    pack.id = id;
    pack.sync_req.client_paths = all_paths;

    if(!send(pack, socket)){
        std::cerr << "Connection error: impossible to send sync packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }



    struct packet response;
    if(!receive(response, socket)){
        std::cerr << "Connection error: impossible to receive sync packets." << std::endl;
        std::cerr << "Shutdowning..." << std::endl;
        return 0;
    }

    if(response.id != id){
        std::cerr << "Error." << std::endl;
        return 0;
    }

    for(auto &file : response.sync_res.modified_paths) {
        fs::path f = file;
        if(!send_file(f, id, ctx)){
            return 0;
        }
    }

    std::cout << "synchronization succeded" << std::endl;
    return 1;
}

struct packet create_modify_request(std::string& id, fs::path& path, enum operation op, fs::file_status& status, void* buf){
    struct packet pack;
    pack.packet_type = modify_request;
    pack.id = id;
    std::string p = path;   //we convert std::filesystem::path to a std::string to void problems like file names with spaces
    pack.mod.path = fs::relative(p, folder);
    pack.mod.op = op;

    //convert fs::permissions to std::string
    fs::perms perms = status.permissions();
    std::string permissions = translate_perms_to_string(perms);
    pack.mod.permissions = permissions;
    if(buf) pack.mod.content = reinterpret_cast<char*>(buf);
    return pack;
}

int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, operation op){
    socket_guard socket(ctx);

    if(fs::is_directory(path)){
        if(op == del){

            /*
             * delete all subfiles and subdirectories recursivly calling send_file()
             *
             * then, send to server the information about the deletion of the folder
             *
             * */

            for(auto& file : fs::directory_iterator(path)){
                if(!send_file((fs::path&)file, id, ctx, del)) return 0;
            }
            std::cout << "delete directory: " << path << std::endl;

            fs::file_status status = fs::status(path);
            struct packet pack = create_modify_request(id, path, del, status, nullptr);

            //send to server
            if(!send(pack, socket)){
                std::cerr << "Connection error: impossible to send modify packets." << std::endl;
                std::cerr << "Shutdowning..." << std::endl;
                return 0;
            }
            return 1;
        }
        else {
            // send path to server
            fs::file_status status = fs::status(path);
            struct packet pack = create_modify_request(id, path, create, status, nullptr);

            //send to server
            if(!send(pack, socket)){
                std::cerr << "Connection error: impossible to send modify packets." << std::endl;
                std::cerr << "Shutdowning..." << std::endl;
                return 0;
            }

            return 1;
        }
    }
    else if(op == del){
        // send to server the information about the deletion of the file

        fs::file_status status = fs::status(path);
        struct packet pack = create_modify_request(id, path, del, status, nullptr);
        std::cout << "path: " << pack.mod.path << " " << "op: " << pack.mod.op << std::endl;

        //send to server
        if(!send(pack, socket)){
            std::cerr << "Connection error: impossible to send modify packets." << std::endl;
            std::cerr << "Shutdowning..." << std::endl;
            return 0;
        }

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
             *  if i == 0, then server will create a new file, else server will append content in an existing file;
             *
             *  we send to the server create for i == 0; append for i != 0; then, we send an end message
             *  in any case, in the message there will be the content of the file
             */

            fs::file_status status = fs::status(path);
            struct packet pack = create_modify_request(id, path, i==0? create : append, status, buf);

            //send to server
            if(!send(pack, socket)){
                std::cerr << "Connection error: impossible to send modify packets." << std::endl;
                std::cerr << "Shutdowning..." << std::endl;
                return 0;
            }

            std::cout << "path: " << pack.mod.path << " " << "op: " << pack.mod.op << std::endl;
            i++;
        }
        fs::file_status status = fs::status(path);
        struct packet pack = create_modify_request(id, path, end, status, nullptr);

        //send to server
        if(!send(pack, socket)){
            std::cerr << "Connection error: impossible to send modify packets." << std::endl;
            std::cerr << "Shutdowning..." << std::endl;
            return 0;
        }

        std::cout << "path: " << pack.mod.path << " " << "op: " << pack.mod.op << std::endl;

        in.close();
        free(buf);
        return 1;
    }
}

int send(struct packet & pack, socket_guard &socket){
    //preparing the archive to send
    boost::asio::streambuf buf;
    std::ostream os(&buf);
    boost::archive::text_oarchive ar(os);
    ar & pack;

    boost::system::error_code err;
    socket.socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(SERVER), 9999),
                          err);
    if (err.failed()) {
        std::cout << "Send failed." << std::endl;
        return 0;
    }

    const size_t header = buf.size();

    // send header and buffer using scatter
    std::vector<boost::asio::const_buffer> buffers;
    buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
    buffers.push_back(buf.data());

    const size_t rc = boost::asio::write(socket.socket, buffers);
    std::cout << "Packet send." << std::endl;

    return rc;
}

int receive(struct packet & pack, socket_guard &socket){
    size_t header;
    boost::system::error_code err;

    boost::asio::read(socket.socket, boost::asio::buffer(&header, sizeof(header)), err);

    if (err.failed()) {
        std::cout << "Receive failed." << std::endl;
        return 0;
    }

    // read body
    boost::asio::streambuf buf;
    const size_t rc = boost::asio::read(socket.socket, buf.prepare(header), err);

    if (err.failed()) {
        std::cout << "Receive failed." << std::endl;
        return 0;
    }

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