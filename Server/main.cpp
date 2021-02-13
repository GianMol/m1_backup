#include "Packets.h"

namespace fs = std::filesystem;
#define FILE_PATHS "/Users/damiano/Documents/GitHub/m1_backup/Support/server_paths.txt"
#define FILE_PATH_LENGTH 300

//Global variables
std::string files[5];//certificate, private_key, dh, sqlite, backup;
std::map<std::string, std::string> tokens = {
        {"21908767", "0"},
        {"27898909", "0"},
        {"34567892", "0"},
        {"98345678", "0"},
        {"67905423", "0"},
        {"54096523", "0"},
        {"90124567", "0"},
        {"56903456", "0"},
        {"21345678", "0"}
};

using boost::asio::ip::tcp;

/* -------------------- Session -------------------- */
class session : public std::enable_shared_from_this<session> {
public:
    session(tcp::socket sock, boost::asio::ssl::context& ssl_context)
            : socket(std::move(sock), ssl_context), header(1) {}

    void start(){
        handshake();
    }

private:
    boost::asio::ssl::stream<tcp::socket> socket;
    size_t header;

    //TLS handshake
    void handshake(){
        auto self(shared_from_this());
        boost::system::error_code error;
        socket.handshake(boost::asio::ssl::stream_base::server, error);

        if(!error){
            try {
                execute_task();
            }
            catch (boost::system::error_code& error){
                std::cerr << "Error: " << error.message() << std::endl;
            }
            catch (std::iostream::failure& error){
                std::cerr << "Exception opening/reading/closing file: " << error.what() << std::endl;
                struct response res;
                res.gen_res.res = false;
                res.gen_res.description = "Server Error";
                send(res);
            }
            catch (fs::filesystem_error& error){
                std::cerr << "Filesystem exception: " << error.what() << std::endl;
                struct response res;
                res.gen_res.res = false;
                res.gen_res.description = "Server Error";
                send(res);
            }
            catch (std::invalid_argument& error){
                std::cerr << "Invalid argument exception: " << error.what() << std::endl;
                struct response res;
                res.gen_res.res = false;
                res.gen_res.description = "Server Error";
                send(res);
            }
            catch (std::logic_error& error){
                std::cerr << "Logic error exception: " << error.what() << std::endl;
                struct response res;
                res.gen_res.res = false;
                res.gen_res.description = "Server Error";
                send(res);
            }
            catch (std::exception& error){
                std::cerr << "Generic error: " << error.what() << std::endl;
                struct response res;
                res.gen_res.res = false;
                res.gen_res.description = "Server Error";
                send(res);
            }
        }
        else {
            std::cerr << "Handshake failed: " << error.message() << "\n";
        }
    }

    //Generation of random token
    static void gen_random(std::string& result, const int& len) {
        std::stringstream ss;
        unsigned char alphanum[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";
        unsigned char s [len];

        for (int i = 0; i < len; ++i) {
            s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }

        for(int i = 0; i < len; i++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)s[i];
        }

        s[len] = 0;
        result = ss.str();
    }

    //Send packet
    int send (struct response pack){
        boost::asio::streambuf buf;
        boost::system::error_code err;
        std::ostream os(&buf);
        boost::archive::text_oarchive ar(os);

        //Serialization
        ar & pack;

        const size_t header_res = buf.size();

        //Send header and buffer using scatter
        std::vector<boost::asio::const_buffer> buffers;
        buffers.push_back(boost::asio::buffer(&header_res, sizeof(header_res)));
        buffers.push_back(buf.data());

        const size_t rc = boost::asio::write(socket, buffers, err);
        if (err) {
            std::cerr << "Send failed: " << err.message() << std::endl;
            return 0;
        }
        return rc;
    }

    //Function executed by threads
    void execute_task() {
        boost::asio::streambuf stream;
        struct request received;

        //Read header
        boost::asio::read(socket, boost::asio::buffer(&header, sizeof(header)));

        //Read body
        boost::asio::read(socket, stream.prepare(header));
        stream.commit(header);

        //Deserialization
        std::istream is(&stream);
        boost::archive::text_iarchive ar(is);
        ar & received;

        //Switch based on the received packet type
        switch (received.packet_type) {
            case type::sync_request: {
                struct response res_synch;

                //Hanlding of request
                if(!manage_synch(received, res_synch)){
                    std::cerr << "User: " << received.id << ", synchronization error" << std::endl;
                }

                //Send res to client
                if(!send(res_synch)){
                    std::cerr << "User: " << received.id << ", sending error" << std::endl;
                }
                break;
            }
            case type::auth_request: {
                struct response res_auth;

                if(!manage_auth(received, res_auth)){
                    std::cerr <<"User: " << received.id << ", authentication error" << std::endl;
                }

                //Send res to client
                if(!send(res_auth)){
                    std::cerr << "User: " << received.id << ", sending error" << std::endl;
                }
                break;
            }
            case type::modify_request: {
                struct response res_mod;

                if(!manage_modify(received, res_mod)){
                    std::cerr <<"User: " << received.id << ", modification error" << std::endl;
                }

                //Send res to the client
                if(!send(res_mod)){
                    std::cerr << "User: " << received.id << ", sending error" << std::endl;
                }
                break;
            }
            case type::down_request: {
                struct response res;

                if(!manage_down(received, res)){
                    std::cerr <<"User: " << received.id << ", download error" << std::endl;
                }

                //Send res to the client
                if(!send(res)){
                    std::cerr << "User: " << received.id << ", sending error" << std::endl;
                }
                break;
            }
            case type::file_request: {
                struct response res;

                if(!manage_file(received, res)){
                    std::cerr <<"User: " << received.id << ", download file error" << std::endl;
                }

                //Send res to the client
                if(!send(res)){
                    std::cerr << "User: " << received.id << ", sending error" << std::endl;
                }
                break;
            }
            default:
                break;
        }
    }

    //Computation of passwords hash
    std::string compute_pass_hash (std::string pass_clear){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, pass_clear.c_str(), pass_clear.size());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        std::string hashed = ss.str();
        return hashed;
    }

    //Computation of files hash
    int compute_hash(fs::path& path, std::string& hash){
        if(!fs::exists(path))
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

    //Handling synchronization requests
    int manage_synch (struct request& req, struct response& res){

        //Check whether request is authenticated
        if(tokens.find(req.id)->second != req.token){
            res.gen_res.res = false;
            res.gen_res.description = "User not authorized";
            return 0;
        }

        std::map <std::string, std::string> current_hashs;
        std::map <std::string, std::string>::iterator it;
        std::map <std::string, std::string> path_to_check;
        std::string aux;
        std::string hash;
        std::string string_folder = files[4] +  req.id + "/backup/";
        fs::path folder = string_folder;

        //Check the existance of user's backup folder
        if(!fs::exists(folder)) {
            res.gen_res.res = false;
            res.gen_res.description = "Error: directory doesn't exist";
            return 0;
        }

        //Server checks if these paths are beign modified or not. The modified one wll be inserted into a vector
        //Compute hashes of all server files and folders
        //Initialization of sevver files map current_hashes (key:path, value:hash)
        for(auto &file : fs::recursive_directory_iterator(folder)) {
            if(fs::is_directory(file)){
                std::pair<std::string, std::string> pair = std::make_pair(fs::relative(file, folder), "\0");//In presence of a folder, corresponding hash value is set to \0
                current_hashs.insert(pair);
            }
            else if(!compute_hash((fs::path &) file, hash)){
                res.gen_res.res = false;
                res.gen_res.description = "Error: hash failed";
                return 0;
            }
            else {
                current_hashs.insert(std::pair<std::string, std::string>(fs::relative(file, folder).string(), hash));
            }
        }

        //Comparison between the computed local files map and the one received from client (which is the representation of current client status)
        //Files which are not present in local folder or which are not updated are inserted into a vector called modified_paths inside the response packet
        for (it=req.sync_req.client_paths.begin(); it!=req.sync_req.client_paths.end(); it++){
            auto position = current_hashs.find(it->first);
            if(position==current_hashs.end()){
                res.sync_res.modified_paths.push_back(it->first);
            }
            else{
                if(position->second!=it->second) {
                    res.sync_res.modified_paths.push_back(it->first);
                }
            }
        }

        //Delete elements of server folder which are not present in client
        for(auto& path : current_hashs){
            auto position = req.sync_req.client_paths.find(path.first);
            if(position == req.sync_req.client_paths.end()){
                std::filesystem::remove_all(string_folder + path.first);
            }
        }
        res.gen_res.res = true;
        return 1;
    }

    //Handling modify requests
    int manage_modify (struct request& req, struct response& res) {

        //Check whether request is authenticated
        if(tokens.find(req.id)->second != req.token){
            res.gen_res.res = false;
            res.gen_res.description = "User not authorized";
            return 0;
        }

        std::string received_path = req.mod.path;
        std::string relative_path = received_path.substr(received_path.find_last_of('/') + 1, received_path.length());

        //Each user has a unique folder (idenitfied by id), containing two subfolders:
        //backup: it contains a complete backup of user's local folder
        //temp: it could contain temporary data computed during operations performed on backup files and allow retrieving old versions of files in case of errors
        std::string back_folder = files[4] + req.id + "/backup/";
        std::string temp_folder = files[4] + req.id + "/temp/";
        std::string path_to_manage = back_folder + received_path;
        std::string path_to_temp = temp_folder + relative_path;
        fs::path current (path_to_manage);
        fs::path temp_folder_file (path_to_temp);
        std::ifstream ifile;

        //In case of create
        if(req.mod.op==operation::create) {
            if(req.mod.is_directory){
                fs::create_directory(path_to_manage);
                res.gen_res.res = true;
                return 1;
            }
            else {
                //If path already exists
                if(fs::exists(path_to_manage)){

                    //Copy file into temp folder so that it can be retrieved in case of errors
                    if(!std::filesystem::copy_file(path_to_manage, temp_folder_file)){
                        res.gen_res.res = false;
                        res.gen_res.description = "Server error";
                        return 0;
                    }

                    //Remove old version of file
                    if(!std::filesystem::remove(path_to_manage)){
                        res.gen_res.res = false;
                        res.gen_res.description = "Server error";
                        return 0;
                    }
                }

                //Creation of a new file
                std::ofstream fs(path_to_manage);

                //In case of errors
                if (!fs) {

                    //If the file exists in temporary folder, copy it into backup folder and then remove it from temp folder
                    if(fs::exists(temp_folder_file)){
                        if(!std::filesystem::copy_file(temp_folder_file, path_to_manage)){
                            res.gen_res.res = false;
                            res.gen_res.description = "Server error";
                            return 0;
                        }

                        if(!std::filesystem::remove(temp_folder_file)){
                            res.gen_res.res = false;
                            res.gen_res.description = "Server error";
                            return 0;
                        }
                    }

                    res.gen_res.res = false;
                    res.gen_res.description = "Server error";
                    return 0;
                }

                //Insert content into file
                fs << req.mod.content;

                if(fs.bad()){

                    //If the file exists in temporary folder, copy it into backup folder and then remove it from temp folder
                    if(fs::exists(temp_folder_file)){
                        if(!std::filesystem::copy_file(temp_folder_file, path_to_manage)){
                            res.gen_res.res = false;
                            res.gen_res.description = "Server error";
                            return 0;
                        }

                        if(!std::filesystem::remove(temp_folder_file)){
                            res.gen_res.res = false;
                            res.gen_res.description = "Server error";
                            return 0;
                        }
                    }

                    res.gen_res.res = false;
                    res.gen_res.description = "Server error";
                    return 0;
                }

                fs.close();

                //In case of successfully creation, if the file is present in temp folder, it is removed
                if(fs::exists(temp_folder_file)) {
                    if(!std::filesystem::remove(temp_folder_file)){
                        std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
                        std::filesystem::permissions(current, perms);
                        res.gen_res.res = true; //True because it doesn't affect the client
                        return 0;
                    }
                }
            }

            std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
            std::filesystem::permissions(current, perms);
            res.gen_res.res = true;
            return 1;
        }

        //In case of deletion
        else if (req.mod.op==del) {

            //In case path is a directory
            if (fs::is_directory(current)){

                //In case path exists
                if (fs::exists(current)) {
                    if (!std::filesystem::remove_all(current)) {
                        res.gen_res.res = false;
                        res.gen_res.description = "Server error";
                        return 0;
                    } else {
                        res.gen_res.res = true;
                        return 1;
                    }
                }
                //In case path doesn't exist, server doesn't anything
                res.gen_res.res = true;
                return 1;

            }

            //In case path is an existent file
            else if (fs::exists(path_to_manage)) {
                if (!std::filesystem::remove(current)) {
                    res.gen_res.res = false;
                    res.gen_res.description = "Server error";
                    return 0;
                } else {
                    res.gen_res.res = true;
                    return 1;
                }
            }
            //In case path doesn't exist, server doesn't anything
            res.gen_res.res = true;
            return 1;
        }
        else {
            res.gen_res.res = false;
            res.gen_res.description = "Operation not supported.";
            return 0;
        }
    }

    //Handling download requests
    int manage_down (struct request& req, struct response& res) {

        //Check whether request is authenticated
        if(tokens.find(req.id)->second != req.token){
            res.gen_res.res = false;
            res.gen_res.description = "User not authorized";
            return 0;
        }

        std::string directory = files[4] + req.id + "/backup/";
        std::map<std::string, std::string> all_paths;

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
                        res.gen_res.res = false;
                        res.gen_res.description = "Server error";
                        return 0;
                    }
                    else {
                        all_paths.insert(std::pair<std::string, std::string>(fs::relative(file, directory), hash));
                    }
                }
            }
        }

        res.packet_type = down_response;
        res.id = req.id;
        res.gen_res.res = true;
        res.token = req.token;
        res.down_res.server_paths = all_paths;
        return 1;
    }

    //Handling download file requests
    int manage_file (struct request& req, struct response& res) {
        std::ifstream in;
        std::string absolute_path = files[4] + req.id + "/backup/" + req.file_req.path;

        //Read file content
        in.open(absolute_path, std::ios::binary);

        if (!in.is_open()) {
            res.gen_res.description = "Error in opening file";
            res.gen_res.res = false;
            return 0;
        }

        std::streambuf *buf;
        buf = in.rdbuf();

        if (in.bad()) {
            res.gen_res.description = "Error in opening file";
            res.gen_res.res = false;
            return 0;
        }

        std::string content((std::istreambuf_iterator<char>(buf)), std::istreambuf_iterator<char>());
        fs::file_status status = fs::status(req.file_req.path);

        res.id = req.id;
        res.packet_type = file_response;
        res.file_res.content = content;
        res.token = req.token;
        res.file_res.path = req.file_req.path;
        fs::path p = absolute_path;
        res.file_res.is_directory = fs::is_directory(p);

        //convert fs::permissions to std::string
        fs::perms perms = status.permissions();
        std::string permissions = translate_perms_to_string(perms);
        res.file_res.permissions = permissions;
        res.gen_res.res = true;

        in.close();
        return 1;
    }

    //Handling authentication requests
    int manage_auth (struct request& req, struct response& res) {
        sqlite3* db;
        sqlite3_stmt* result;
        std::string query;

        if(sqlite3_open(files[3].c_str(), &db) == 0) {
            query = "SELECT Password FROM utenti WHERE ID=?";
            sqlite3_prepare( db, query.c_str(), -1, &result, NULL);
            sqlite3_bind_text(result, 1, req.id.c_str(), req.id.length(), SQLITE_TRANSIENT);
            sqlite3_step(result);
            std::string password_db = reinterpret_cast<const char *>(sqlite3_column_text(result, 0));
            std::string password_user = compute_pass_hash (req.auth.password);
            int out = password_db.compare(password_user);

            //Equal digest
            if(out ==0){
                res.gen_res.res=true;
                gen_random(res.token, 512);
                if(tokens.find(req.id) != tokens.end()){
                    tokens.find(req.id) -> second = res.token;
                }
            }
            //Different digest
            else{
                res.gen_res.description="Authentication failed";
                res.gen_res.res=false;
                return 0;
            }
        } else{
            res.gen_res.description="Server error";
            res.gen_res.res=false;
            return 0;
        }
        sqlite3_finalize(result); //Clean up function
        return 1;
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
        int i;
        for(i=0; i < 9; i++){
            if(string[i] != '-') p |= permissions[i];
        }
        return p;
    }

};

class Server{
public:
    //SSL socket is created
    Server(boost::asio::io_context& io_context) : acceptor(io_context, tcp::endpoint(tcp::v4(), 9999)),
                                                  ssl_context(boost::asio::ssl::context::tlsv12){
        //Set TLS options
        ssl_context.set_options(boost::asio::ssl::context::default_workarounds
                                | boost::asio::ssl::context::no_sslv2
                                | boost::asio::ssl::context::single_dh_use);

        ssl_context.set_password_callback(std::bind(&Server::get_password, this));
        ssl_context.use_certificate_chain_file(files[0]);
        ssl_context.use_private_key_file(files[1], boost::asio::ssl::context::pem);
        ssl_context.use_tmp_dh_file(files[2]);

        std::cout<<"Server listening..."<<std::endl;
        //Primitive accept
        accept();
    }

private:
    tcp::acceptor acceptor;
    boost::asio::ssl::context ssl_context;

    std::string get_password() const {
        return "Ciaociao";
    }

    void accept(){
        acceptor.async_accept([this](const boost::system::error_code& error, tcp::socket socket){
            if(!error) {

                //Establish a session with a client
                std::make_shared<session>(std::move(socket), ssl_context)->start();

                //Primitive accept
                accept();
            }
        });
    }
};

//Load of certificate and initialization of parameters (e.g certificate, private_key, dh, sqlite, backup)
int load_certificates(){
    std::ifstream in(FILE_PATHS);
    if(!in) return 0;
    char c[FILE_PATH_LENGTH];
    for(auto & file : files){
        in.getline(c, FILE_PATH_LENGTH);
        if(in.bad()) return 0;
        file = c;
    }
    in.close();
    return 1;
}

int main() {
    if(!load_certificates()){
        std::cerr << "Error: list of certificate files missing. Shutdowning..." << std::endl;
        return 0;
    }
    boost::asio::io_context io_context;

    Server server (io_context);

    //THREAD POOL
    ThreadGuardVector threads(io_context);
}
