/*********** MYLIB **********/
#include "Packets.h"
#include "SocketGuard.cpp"
#include "ThreadGuard.cpp"

#define SERVER "127.0.0.1"
#define PORT "9999"
#define FILE_PATHS "/Users/damiano/Documents/GitHub/m1_backup/Support/client_paths.txt"
#define FILE_PATH_LENGTH 300
#define ATTEMPTS 5

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
    int i;
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
    //Number of failure attempts
    int counter = 0;

    while(counter < ATTEMPTS) {
        try {
            std::map<std::string, std::string> all_paths;

            if (!fs::is_directory(directory)) {
                std::cerr << "Error: it is not a directory." << std::endl;
                return 0;
            }

            //Initialization all_path map (key: path, value: hash)
            for (auto &file : fs::recursive_directory_iterator(directory)) {
                std::string str_folder = (fs::path) file;
                int pos = str_folder.find_last_of('/');
                std::string str_file = str_folder.substr(pos, str_folder.length());
                if (str_file.at(1) != '~') {
                    std::string pr = (fs::path) file;
                    if (fs::is_directory(file)) {
                        std::pair<std::string, std::string> pair = std::make_pair(fs::relative(file, directory), "\0");
                        all_paths.insert(pair);
                    } else {
                        std::string hash;
                        if (!compute_hash((fs::path &) file, hash)) {
                            std::cerr << "Error in computing hash." << std::endl;
                            throw std::exception();
                        } else {
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

            if (send_receive(pack, response, ctx, ssl_ctx, endpoint) != 1) {
                return response.gen_res.res;

            }
            for (auto &file : response.sync_res.modified_paths) {
                fs::path f = file;
                if (!send_file(f, id, ctx, ssl_ctx, endpoint)) {
                    throw std::exception();
                }
            }
            return 1;
        }
        catch(fs::filesystem_error& error) {
            //In case of filesystem errors, counter is increased
            counter++;
            std::cout << "Synchronization failed" << std::endl;
            std::cout << "Remaining attempts: " << ATTEMPTS-counter << std::endl;

            if(counter < ATTEMPTS){
                std::cout << "Retrying..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            }
        }
        catch (std::exception& error){
            counter++;
            std::cout << "Synchronization failed" << std::endl;
            std::cout << "Remaining attempts: " << ATTEMPTS-counter << std::endl;

            if(counter < ATTEMPTS){
                std::cout << "Retrying..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            }
        }
    }
    return 0;
}

//Initialization of struct request
struct request create_modify_request(std::string& id, fs::path& path, enum operation op, fs::file_status& status, std::string& buf, bool valid_content=true){
    struct request pack;
    pack.id = id;
    pack.packet_type = modify_request;
    pack.token = token;
    std::string p = path.string();
    pack.mod.path = fs::relative(p, folder);
    pack.mod.op = op;

    if(op!=del)
        pack.mod.is_directory = fs::is_directory(p);

    //Convert fs::permissions to std::string
    fs::perms perms = status.permissions();
    std::string permissions = translate_perms_to_string(perms);
    pack.mod.permissions = permissions;

    //Valid content for files (not valid for delete and folders)
    if(valid_content)
        pack.mod.content = buf;
    return pack;
}

//Initialization related to request type
int send_file(fs::path& path, std::string& id, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint, operation op){
    //Find and ignore not valid files (e.g. temporary files like ~name_file created by Microsoft Word)
    int pos = path.string().find_last_of('/');
    if (pos != -1) {
        std::string str_file = path.string().substr(pos, path.string().length());
        if (str_file.at(1) == '~') {
            return 1;
        }
    } else {
        if (path.string().at(0) == '~')
            return 1;
    }

    //path: relative path
    //path_to_manage: absolute path
    std::string path_to_manage = folder.string() + path.string();

    //Create operation for directories
    if (op == create && fs::exists(path_to_manage) && fs::is_directory(path_to_manage)) {
        fs::file_status status = fs::status(path_to_manage);
        struct request pack = create_modify_request(id, reinterpret_cast<fs::path &>(path_to_manage), create,
                                                    status, (std::string &) " ", false);

        struct response res;
        if (send_receive(pack, res, ctx, ssl_ctx, endpoint) != 1) {
            return res.gen_res.res;
        }
    }
        //Delete operation
    else if (op == del) {
        fs::file_status status = fs::status(path_to_manage);
        struct request pack = create_modify_request(id, reinterpret_cast<fs::path &>(path_to_manage), del, status,
                                                    (std::string &) " ", false);

        struct response res;
        if (send_receive(pack, res, ctx, ssl_ctx, endpoint) != 1) {
            return res.gen_res.res;
        }
    }
        //Create and modify operation for files
    else {
        if(fs::exists(path_to_manage)) {
            //Open file
            std::ifstream in;
            in.open(path_to_manage, std::ios::binary);
            if (!in.is_open()) {
                return 0;
            }
            std::streambuf *buf;

            //Read content of file
            buf = in.rdbuf();

            if (in.bad())
                return 0;

            std::string content((std::istreambuf_iterator<char>(buf)), std::istreambuf_iterator<char>());
            fs::file_status status = fs::status(path_to_manage);
            struct request pack = create_modify_request(id, reinterpret_cast<fs::path &>(path_to_manage), create,
                                                        status, content);
            struct response res;


            if (send_receive(pack, res, ctx, ssl_ctx, endpoint) != 1) {
                return res.gen_res.res;
            }
            in.close();
        }
        else {
            return 0;
        }
    }
    return 1;
}

//File watcher to monitor changes on target folder, it is called as handler by a secondary thread
void file_watcher(){
    FileWatcher fw{folder, std::chrono::milliseconds(5000)};
    while (true) {
        try {
            fw.start([](std::string &path_to_watch, FileStatus status) -> void {
                struct pair p;
                p.path = path_to_watch;
                std::unique_lock<std::mutex> ul(m);

                if (!fs::is_regular_file(fs::path(path_to_watch)) && status != FileStatus::erased) {
                    if (fs::is_directory(path_to_watch) && status == FileStatus::created) {
                        invalid.emplace_back(path_to_watch);
                        p.status = FileStatus::created;
                        queue.push(p);
                        cv.notify_all();
                    }
                    return;
                }

                switch (status) {
                    case FileStatus::created:
                        invalid.emplace_back(path_to_watch);
                        p.status = FileStatus::created;
                        queue.push(p);
                        cv.notify_all();
                        break;
                    case FileStatus::modified:
                        invalid.emplace_back(path_to_watch);
                        p.status = FileStatus::modified;
                        queue.push(p);
                        cv.notify_all();
                        break;
                    case FileStatus::erased:
                        auto it = std::find(invalid.begin(), invalid.end(), path_to_watch);
                        if (it != invalid.end()) {
                            invalid.erase(it);
                        }
                        p.status = FileStatus::erased;
                        queue.push(p);
                        cv.notify_all();
                        break;
                }
            });
        }
        catch (fs::filesystem_error &error) {
            //Exception raised from last_write_time and recursive_iterator functions
            continue;
        }
    }
}

//Authentication function
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

//Description in case of error
int process_response(struct response& pack){
    if(!pack.gen_res.res)
        std::cerr << pack.gen_res.description << std::endl;
    return pack.gen_res.res;
}

//Load of certificate and initialization of parameters (e.g global folder variable)
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

//Download of server content into local folder: choice 1 of Menu
int down(std::string& id, boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint) {
    //Number of failure attempts
    int counter = 0;

    while(counter < ATTEMPTS) {
        try {
            std::map<std::string, std::string> all_paths;

            struct request pack;
            pack.packet_type = down_request;
            pack.id = id;
            pack.token = token;

            struct response response;

            if (send_receive(pack, response, ctx, ssl_ctx, endpoint) != 1) {
                return response.gen_res.res;
            }

            std::map<std::string, std::string> current_hashs;
            std::map<std::string, std::string>::iterator it;
            std::string hash;
            std::vector<std::string> different_paths;

            //Initialization of local files map current_hashes (key:path, value:hash)
            for (auto &file : fs::recursive_directory_iterator(folder)) {
                if (fs::is_directory(file)) {
                    std::pair<std::string, std::string> pair = std::make_pair(fs::relative(file, folder),"\0");//In presence of a folder, corresponding hash value is set to \0
                    current_hashs.insert(pair);
                } else if (!compute_hash((fs::path &) file, hash)) {
                    std::cerr << "Error: hash failed" << std::endl;
                    throw std::exception();
                } else {
                    current_hashs.insert(std::pair<std::string, std::string>(fs::relative(file, folder).string(), hash));
                }
            }

            //Comparison between the computed local files map and the one received from server (which is the representation of current server status)
            //Files which are not present in client folder or which are not updated are inserted into a vector called different_paths
            for (it = response.down_res.server_paths.begin(); it != response.down_res.server_paths.end(); it++) {
                auto position = current_hashs.find(it->first);
                if (position == current_hashs.end()) {
                    different_paths.push_back(it->first);
                } else {
                    if (position->second != it->second)
                        different_paths.push_back(it->first);
                }
            }

            //Ask to the server files present in different_paths (ones which are not already present in local folder)
            for (auto &path : different_paths) {
                struct request req;
                req.id = id;
                req.packet_type = file_request;
                req.token = token;
                req.file_req.path = path;
                struct response res;

                if (send_receive(req, res, ctx, ssl_ctx, endpoint) != 1) {
                    return response.gen_res.res;
                }

                //path: relative path
                //path_to_manage: absolute path
                std::string path_to_manage = folder.string() + path;
                if (res.file_res.is_directory) {
                    fs::create_directory(path_to_manage + "/");
                } else {
                    //Open file
                    std::ofstream fs(path_to_manage, std::ios::out);
                    if (!fs) {
                        throw std::exception();
                    }
                    fs << res.file_res.content;
                    if (fs.bad()) {
                        throw std::exception();
                    }
                    fs.close();
                }
                std::filesystem::perms perms = translate_string_to_perms(res.file_res.permissions);
                std::filesystem::permissions(path_to_manage, perms);
            }

            //Delete elements of local folder which are not present in server
            for (auto &path : current_hashs) {
                auto position = response.down_res.server_paths.find(path.first);
                if (position == response.down_res.server_paths.end()) {
                    std::filesystem::remove_all(folder.string() + path.first);
                }
            }

            return 1;
        }
        catch(fs::filesystem_error& error) {
            //In case of filesystem errors, counter is increased
            counter++;
            std::cout << "Download failed" << std::endl;
            std::cout << "Remaining attempts: " << ATTEMPTS-counter << std::endl;

            if(counter < ATTEMPTS){
                std::cout << "Retrying..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            }
        }
        catch (std::exception& error){
            counter++;
            std::cout << "Download failed" << std::endl;
            std::cout << "Remaining attempts: " << ATTEMPTS-counter << std::endl;

            if(counter < ATTEMPTS){
                std::cout << "Retrying..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            }
        }
    }
    return 0;
}

//Check synchronization of a file or a folder: choice 3 of Menu
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

    //path: relative path
    //path_to_manage: absolute path
    std::string path_to_manage = folder.string() + "/" + path;

    //In presence of a file
    if(!fs::is_directory(path_to_manage)){
        auto position = response.down_res.server_paths.find(path);
        if(position==response.down_res.server_paths.end()){
            if(fs::exists(path_to_manage)){
                return -3;
            }
            else {
                return -2;
            }
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
    //In presence of a folder
    else{
        try {
            return check_folder(response, path);
        }
        catch (fs::filesystem_error& error){
            return -2;
        }
    }
}

//Function called by the check function in order to check synchronization of a folder
int check_folder (struct response& res, std::string& path){

    //path: relative_path
    //path_to_manage: absolute_path
    std::string path_to_manage = folder.string() + path;

    //Check synchronization of files and subfolders of the current folder
    for(auto &f : fs::recursive_directory_iterator(path_to_manage)) {
        std::string file = f.path();

        //In case of a file
        if(!fs::is_directory(file)) {
            auto position = res.down_res.server_paths.find(fs::relative(file,folder));
            //File not present in remote backup
            if(position==res.down_res.server_paths.end()){
                return -1;
            }
            else{
                std::string hash;
                if(!compute_hash((fs::path&)file, hash)){
                    return 0;
                }
                //File not syncrhonized
                if(position->second != hash) {
                    return -1;
                }
            }
        }
    }
    //File synchronized
    return 1;
}

//It handles the communication between client and server
int send_receive(struct request& req, struct response& res, boost::asio::io_context & ctx, boost::asio::ssl::context& ssl_ctx, boost::asio::ip::tcp::resolver::results_type& endpoint) {
    //Number of failure attempts
    int counter = 0;

    while(counter < ATTEMPTS) {
        try {
            //Open a socket
            socket_guard socket(ctx, ssl_ctx);
            //Connect primitive of socket
            boost::asio::connect(socket.socket.lowest_layer(), endpoint);
            //TLS handshake between client and server
            socket.socket.handshake(boost::asio::ssl::stream_base::client);

            /*********************** SEND ***********************/
            //Serialization of packet
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

            /*********************** RECEIVE ***********************/
            size_t header_res;
            boost::asio::read(socket.socket, boost::asio::buffer(&header_res, sizeof(header_res)));

            //Read body
            boost::asio::streambuf buf_res;
            boost::asio::read(socket.socket, buf_res.prepare(header_res));
            buf_res.commit(header_res);

            //Deserialization of packet
            std::istream is(&buf_res);
            boost::archive::text_iarchive ar_res(is);
            ar_res & res;

            //Check if the request is authenticated
            if(!res.gen_res.res && res.gen_res.description == "User not authorized"){
                struct request auth_pack;
                auth_pack.id = req.id;
                auth_pack.packet_type = auth_request;
                auth_pack.auth.password = password;

                //If the request is not authenticated, auth function is recalled
                if(auth(auth_pack, ctx, ssl_ctx, endpoint) != 1){
                    return 0;
                }else{
                    continue;
                }
            }
            return process_response(res);

        } catch(boost::system::system_error& error) {
            //In case of network errors, counter is increased
            counter++;
            std::cout << "Remaining attempts: " << ATTEMPTS-counter << std::endl;

            //In case of network errors, thread waits for 2 seconds so that transient errors could disappear
            if(counter < ATTEMPTS){
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            }
        } catch(std::exception& error){
            //In case of non transient errors
            return 0;
        }
    }
    return 0;
}