/*********** MYLIB **********/
#include "Packets.h"
#include "SocketGuard.cpp"
#include "ThreadGuard.cpp"

#define SERVER "127.0.0.1"
#define PORT "9999"
#define FILE_PATHS "/Users/damiano/Documents/GitHub/m1_backup/Support/client_paths.txt"
#define FILE_PATH_LENGTH 300
#define ATTEMPTS 20

namespace fs = std::filesystem;

/***************** GLOBAL VARIABLES ***********************/
fs::path folder; //monitorized folder
std::queue<struct pair> queue; //request queue used by fileWatcher for handling requests
std::mutex m;
std::condition_variable cv;
std::string token; //token needed to autheticate client requests
std::vector<fs::path> invalid;
std::string password;

/***************** PROTOTYPES ***********************/
std::string translate_path_to_cyg(fs::path& path);
std::string translate_path_to_win(fs::path& path);
std::string translate_perms_to_string(fs::perms& p);
fs::perms translate_string_to_perms(std::string& string);
int compute_hash(fs::path& path, std::string& hash);
int sync(fs::path& directory, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);
struct request create_modify_request(std::string& id, fs::path& path, enum operation op,  fs::file_status& status, std::string& buf, bool valid_content);
int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint, operation op = create);
int send(struct request & pack, socket_guard &socket);
int receive(struct response & pack, socket_guard &socket);
void file_watcher();
int auth(struct request& auth_pack, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);
int process_response(struct response& pack);
int load_certificate(std::string& cert);
int down(std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);
int check(std::string& path, std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);
int check_folder (struct response& res, std::string& path);
int send_receive(struct request& req, struct response& res, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint);

/******************** FUNCTIONS *****************************/

//Translation path for Cygwin for Windows
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

//Translation path for Windows
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

//Translation permissions into string
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

//Translation string into permissions
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

//Computation of file/folder hash
int compute_hash(fs::path& path, std::string& hash){
    if(!fs::exists(path) || fs::is_directory(path))
        return 0;
    unsigned char result[MD5_DIGEST_LENGTH];
    boost::iostreams::mapped_file_source src (path.string());
    MD5((unsigned char*)src.data(), src.size(), result);
    std::ostringstream sout;
    sout<<std::hex<<std::setfill('0');
    for (auto c:result)
        sout<<std::setw(2)<<(int)c;
    hash=sout.str();
    return 1;
}

//Initial synchronization: choice 2 of Menu
int sync(fs::path& directory, std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint){
    std::map<std::string, std::string> all_paths;

    if(!fs::is_directory(directory)){
        std::cerr << "Error: it is not a directory." << std::endl;
        return 0;
    }

    //Initialization all_path map (key: path, value: hash)
    for(auto &file : fs::recursive_directory_iterator(directory)) {
        std::string str_folder = (fs::path)file;
        int pos = str_folder.find_last_of('/');
        std::string str_file = str_folder.substr(pos, str_folder.length());
        if(str_file.at(1) != '~'){
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

    struct request pack;
    pack.packet_type = sync_request;
    pack.id = id;
    pack.token = token;
    pack.sync_req.client_paths = all_paths;
    struct response response;

    if(send_receive(pack, response, ctx, ssl_ctx, endpoint) != 1){
        return response.gen_res.res;
    }
    for(auto &file : response.sync_res.modified_paths) {
        fs::path f = file;
        if(!send_file(f, id, ctx, ssl_ctx, endpoint)){
            std::cerr << "Impossible sending file during synchronization phase" << std::endl;
            return 0;
        }
    }
    return 1;
}

//Initialization of struct request
struct request create_modify_request(std::string& id, fs::path& path, enum operation op, fs::file_status& status, std::string& buf, bool valid_content=true){
    //std::cout << folder.string() << path.string() << std::endl;
    //std::cout << path << std::endl;
    struct request pack;
    pack.id = id;
    pack.packet_type = modify_request;
    pack.token = token;
    std::string p = path.string();   //we convert std::filesystem::path to a std::string to void problems like file names with spaces
    pack.mod.path = fs::relative(p, folder);
    pack.mod.op = op;

    if(op!=del) {
        #if defined(__linux__) || defined(linux) || defined(__linux)
                pack.mod.is_directory = fs::is_directory(folder.string()+ "/"+ path.string());
        #else
                pack.mod.is_directory = fs::is_directory(p);
                std::cout << pack.mod.is_directory << std::endl;
                //pack.mod.is_directory = path.string().at(path.string().length() - 1) == '/' ? true : false;
        #endif
    }

    //convert fs::permissions to std::string
    fs::perms perms = status.permissions();
    std::string permissions = translate_perms_to_string(perms);
    pack.mod.permissions = permissions;
    if(valid_content)
        pack.mod.content = buf;
    return pack;
}

//Initialization related to request type
int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint, operation op){
    std::string str_folder = path;
    int pos = str_folder.find_last_of('/');
    if(pos != -1) {
        std::string str_file = str_folder.substr(pos, str_folder.length());
        if (str_file.at(1) == '~') {
            return 1;
        }
    }
    else{
        if(str_folder.at(0) == '~')
            return 1;
    }
    std::string path_to_manage = folder.string() + path.string();
    std::cout << path_to_manage << std::endl;

    if(op == create && fs::is_directory(path_to_manage)){
        // send path to server
        fs::file_status status = fs::status(path_to_manage);
        #if defined(__linux__) || defined(linux) || defined(__linux)
            path += "/";
        #endif
        struct request pack = create_modify_request(id, reinterpret_cast<fs::path&>(path_to_manage), create, status, (std::string&)" ", false);
        struct response res;
        if(send_receive(pack, res, ctx, ssl_ctx, endpoint) != 1){
            return res.gen_res.res;
        }
    }
    else if(op == del){
        // send to server the information about the deletion of the file

        fs::file_status status = fs::status(path_to_manage);
        struct request pack = create_modify_request(id, reinterpret_cast<fs::path&>(path_to_manage), del, status, (std::string&)" ", false);

        struct response res;
        if(send_receive(pack, res, ctx, ssl_ctx, endpoint) != 1){
            return res.gen_res.res;
        }
    }
    else {
        std::ifstream in;
        in.open(path_to_manage, std::ios::binary);
        if (!in.is_open()) {
            return 0;
        }
        std::streambuf *buf;
        buf = in.rdbuf();

        if (in.bad())
            return 0;

        std::string content((std::istreambuf_iterator<char>(buf)), std::istreambuf_iterator<char>());
        fs::file_status status = fs::status(path_to_manage);
        struct request pack = create_modify_request(id, reinterpret_cast<fs::path&>(path_to_manage), create, status, content);
        struct response res;
        if(send_receive(pack, res, ctx, ssl_ctx, endpoint) != 1){
            return res.gen_res.res;
        }
        in.close();
    }
    return 1;
}

//Sending a packet
int send(struct request & pack, socket_guard &socket){

    //Preparing the archive to send
    boost::asio::streambuf buf;
    std::ostream os(&buf);
    boost::archive::text_oarchive ar(os);
    ar & pack;
    boost::system::error_code err;

    const size_t header = buf.size();

    //Send header and buffer using scatter
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

//Receiving a packet
int receive(struct response & pack, socket_guard &socket){
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

    fw.start([] (std::string& path_to_watch, FileStatus status) -> void {
        struct pair p;
        p.path = path_to_watch;
        std::unique_lock<std::mutex> ul(m);

        if(!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
            if(fs::is_directory(path_to_watch) && status == FileStatus::created) {
                invalid.emplace_back(path_to_watch);
                std::cout << "File created: " << std::endl;
                p.status = FileStatus::created;
                queue.push(p);
                cv.notify_all();
            }
            return;
        }


        switch(status) {
            case FileStatus::created:
                invalid.emplace_back(path_to_watch);
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
                invalid.emplace_back(path_to_watch);
                std::cout << "File modified: " << std::endl;

                p.status = FileStatus::modified;
                queue.push(p);
                cv.notify_all();

                break;
            case FileStatus::erased:
                auto it = std::find(invalid.begin(), invalid.end(), path_to_watch);
                if(it != invalid.end()){
                    invalid.erase(it);
                }
                std::cout << "File deleted: " << std::endl;

                p.status = FileStatus::erased;
                queue.push(p);
                cv.notify_all();

                break;
        }
    });
}

int auth(struct request& auth_pack, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint){
    struct response auth_res;
    if(send_receive(auth_pack, auth_res, ctx, ssl_ctx, endpoint)){
        token = auth_res.token;
        return auth_res.gen_res.res;
    }
    else {
        return 0;
    }
}

int process_response(struct response& pack){
    std::cerr << pack.gen_res.description << std::endl;
    return pack.gen_res.res;
}

int load_certificate(std::string& cert){
    std::ifstream in(FILE_PATHS);
    if(!in) return 0;
    char c[FILE_PATH_LENGTH];
    in.getline(c, FILE_PATH_LENGTH);
    if(in.bad()) return 0;
    cert = c;
    in.getline(c, FILE_PATH_LENGTH);
    if(in.bad()) return 0;
    std::string buf = c;
    folder = buf + "/";
    in.close();
    return 1;
}

int down(std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint) {
    std::map<std::string, std::string> all_paths;


    struct request pack;
    pack.packet_type = down_request;
    pack.id = id;
    pack.token = token;
    struct response response;

    if(send_receive(pack, response, ctx, ssl_ctx, endpoint) != 1){
        return response.gen_res.res;
    }

    std::map <std::string, std::string> current_hashs;
    std::map <std::string, std::string>::iterator it;
    std::string hash;
    std::vector<std::string> different_paths;

    for(auto &file : fs::recursive_directory_iterator(folder)) {
        if(fs::is_directory(file)){
            std::pair<std::string, std::string> pair = std::make_pair(fs::relative(file, folder), "\0");
            current_hashs.insert(pair);
        }
        else if(!compute_hash((fs::path &) file, hash)){
            std::cerr << "Error: hash failed" << std::endl;
            return 0;
        }
        else {
            current_hashs.insert(std::pair<std::string, std::string>(fs::relative(file, folder).string(), hash));
        }
    }

    for (it=response.down_res.server_paths.begin(); it!=response.down_res.server_paths.end(); it++){
        auto position = current_hashs.find(it->first);
        if(position==current_hashs.end()){//Path non presente, bisogna inserirlo nel vettore
            different_paths.push_back(it->first);
        }
        else{
            if(position->second!=it->second)//Hash diversi
                different_paths.push_back(it->first);
        }
    }

    for(auto& path : different_paths){

        struct request req;
        req.id = id;
        req.packet_type = file_request;
        req.token = token;
        req.file_req.path = path;
        struct response res;
        std::cout << path << std::endl;

        if(send_receive(req, res, ctx, ssl_ctx, endpoint) != 1){
            return response.gen_res.res;
        }

        if(res.file_res.path != path){
            std::cerr << "Different paths" << std::endl;
            std::cerr << "Shutdowning..." << std::endl;
            return 0;
        }

        std::string path_to_manage = folder.string()  + path;
        std::cout << path_to_manage << std::endl;
        if(res.file_res.is_directory){
            fs::create_directory(path_to_manage + "/");
        }
        else {
            std::ofstream fs(path_to_manage, std::ios::out);
            if (!fs) {
                std::cerr << "Error: impossible opening file." << std::endl;
                std::cerr << "Shutdowning..." << std::endl;
                return 0;
            }
            fs << res.file_res.content;
            if(fs.bad()){
                std::cerr << "Error: Impossible writing on the file." << std::endl;
                return 0;
            }
            fs.close();
        }

        std::filesystem::perms perms = translate_string_to_perms(res.file_res.permissions);
        std::filesystem::permissions(path_to_manage, perms);
    }

    for(auto& path : current_hashs){
        auto position = response.down_res.server_paths.find(path.first);
        if(position == response.down_res.server_paths.end()){
            std::filesystem::remove_all(folder.string() + path.first);
        }
    }

    return 1;
}

int check(std::string& path, std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint){
    std::map<std::string, std::string> all_paths;


    struct request pack;
    pack.packet_type = down_request;
    pack.id = id;
    pack.token = token;
    struct response response;
    if(send_receive(pack, response, ctx, ssl_ctx, endpoint) != 1){
        return response.gen_res.res;
    }
    std::string path_to_manage = folder.string() + "/" + path;

    if(!fs::is_directory(path_to_manage)){
        auto position = response.down_res.server_paths.find(path);
        if(position==response.down_res.server_paths.end()){
            return -1;
        }
        else{
            std::string hash;
            compute_hash((fs::path&)path_to_manage, hash);

            if(position->second == hash)//Hash diversi
                return 1;
            else
                return -1;
        }
    }
    else{
        return check_folder(response, path);
    }
}

int check_folder (struct response& res, std::string& path){
    std::string hash;
#if defined(__linux__) || defined(linux) || defined(__linux)
    std::string path_to_manage = folder.string() + "/" + path;
#else
    std::string path_to_manage = folder.string() + path;
#endif

    for(auto &f : fs::recursive_directory_iterator(path_to_manage)) {
        std::string file = f.path();
        std::cout<<file<<std::endl;
        if(fs::is_directory(file)) {
            std::string str = fs::relative(file, folder);
            return check_folder(res, str);
        }
        else {
            auto position = res.down_res.server_paths.find(fs::relative(file,folder));
            if(position==res.down_res.server_paths.end()){
                std::cout<<"Primo if"<<std::endl;
                return -1;
            }
            else{
                std::string hash;
                if(!compute_hash((fs::path&)file, hash)){
                    return 0;
                }
                if(position->second != hash) {
                    std::cout<<hash<<std::endl;
                    std::cout<<position->second<<std::endl;
                    return -1;
                }
            }
        }
    }
    return 1;
}

int send_receive(struct request& req, struct response& res, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint) {
    int counter = 0;

    while(counter < ATTEMPTS) {
        try {
            socket_guard socket(ctx, ssl_ctx);
            boost::asio::connect(socket.socket.lowest_layer(), endpoint);
            socket.socket.handshake(boost::asio::ssl::stream_base::client);

            boost::asio::streambuf buf_req;
            std::ostream os(&buf_req);
            boost::archive::text_oarchive ar_req(os);
            ar_req & req;
            const size_t header_req = buf_req.size();

            //Send header and buffer using scatter
            std::vector<boost::asio::const_buffer> buffers;
            buffers.push_back(boost::asio::buffer(&header_req, sizeof(header_req)));
            buffers.push_back(buf_req.data());
            boost::asio::write(socket.socket, buffers);
            std::cout << "Packet sent." << std::endl;


            size_t header_res;
            boost::asio::read(socket.socket, boost::asio::buffer(&header_res, sizeof(header_res)));

            // read body
            boost::asio::streambuf buf_res;
            boost::asio::read(socket.socket, buf_res.prepare(header_res));

            std::cout << "Packet received." << std::endl;

            buf_res.commit(header_res);

            // deserialize
            std::istream is(&buf_res);
            boost::archive::text_iarchive ar_res(is);
            ar_res & res;
            if(!res.gen_res.res && res.gen_res.description == "User not authorized"){
                struct request auth_pack;
                auth_pack.id = req.id;
                auth_pack.packet_type = auth_request;
                auth_pack.auth.password = password;
                if(auth(auth_pack, ctx, ssl_ctx, endpoint) != 1){
                    return 0;
                }else{
                    continue;
                }
            }
            return process_response(res);

        } catch(boost::system::system_error error) {
            counter++;
            std::cout << counter << std::endl;
            if(counter < ATTEMPTS){
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            }
        }
    }
    return 0;
}