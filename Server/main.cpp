#include <iostream>
#include "FileWatcher.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <map>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>
#include <future>
#include <cstdio>
#include <thread>
#include <queue>
#include <sqlite3.h>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>


namespace fs = std::filesystem;
#define SIZE 1024

//global variable socket
fs::path backup = "/Users/damiano/Desktop/Backup";
std::string id ="10";

//TASK TO EXECUTE
//std::queue<std::queue <struct auth_request>> tasks;
std::queue<boost::asio::ip::tcp::socket> queues; //Coda di socket

enum operation {create, del};
enum type {modify_request, sync_request, sync_single_file_request, sync_response, auth_request, response};

struct auth_request{
    std::string password;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & password;
    }
};

struct response{
    bool res;
    std::string description;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & res;
        ar & description;
    }
};

struct modify_request{
    std::string path;
    operation op;
    std::string content;
    std::string permissions;
    bool is_directory;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & path;
        ar & op;
        ar & content;
        ar & permissions;
        ar & is_directory;
    }
};

struct sync_request{
    std::map<std::string, std::string> client_paths;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & client_paths;
    }
};

struct sync_response{
    std::vector<std::string> modified_paths;
    bool res;
    std::string description;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & modified_paths;
        ar & res;
        ar & description;
    }
};

struct packet{
    std::string id;
    type packet_type;
    struct auth_request auth;
    struct modify_request mod;
    struct response res;
    struct sync_request sync_req;
    struct sync_response sync_res;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & id;
        ar & packet_type;
        ar & auth;
        ar & mod;
        ar & res;
        ar & sync_req;
        ar & sync_res;
    }

};

struct pair{
    fs::path path;
    FileStatus status;
};


using boost::asio::ip::tcp;

/* -------------------- SESSION -------------------- */
class session : public std::enable_shared_from_this<session> {
public:
    session(tcp::socket sock, boost::asio::ssl::context& ssl_context)
            : socket(std::move(sock), ssl_context) {}

    void start(){
        handshake();
    }

private:
    boost::asio::ssl::stream<tcp::socket> socket;
    char data_[1024];
    size_t header;

    void handshake(){
        auto self(shared_from_this());
        boost::system::error_code error;
        socket.handshake(boost::asio::ssl::stream_base::server, error);

        if(!error){
            execute_task();
        }
        else {
            std::cout << "Handshake failed: " << error.message() << "\n";
        }
    }

    void send (struct packet pack){
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

        const size_t rc = boost::asio::write(socket, buffers, err);
        if (err) {
            std::cout << "Send failed: " << err.message() << std::endl;
        }
        std::cout << "Packet send." << std::endl;
    }

    void execute_task() {
            std::cout << "Thread in esecuzione" << std::endl;
            boost::asio::streambuf stream;
            struct packet received;
            boost::asio::read(socket, boost::asio::buffer(&header, sizeof(header)));

            //Body is
            boost::asio::read(socket, stream.prepare(header));
            stream.commit(header);

            //Deserializzazione
            std::istream is(&stream);
            boost::archive::text_iarchive ar(is);
            ar & received;

            switch (received.packet_type) {
                /**************************SYNCH REQUEST****************************/
                case type::sync_request: {
                    struct packet res_synch;
                    manage_synch(received, res_synch);

                    //Send res to the client
                    std::vector<std::string>::iterator it;
                    for(it=res_synch.sync_res.modified_paths.begin(); it!=res_synch.sync_res.modified_paths.end(); it++){
                        std::cout << *it << std::endl;
                    }
                    send(res_synch);
                    break;
                }
                case type::auth_request: {
                    struct packet res_auth;
                    manage_auth(received, res_auth);
                    //Send res to the client
                    send(res_auth);
                    break;
                }
                case type::modify_request: {
                    /***************************MODIFY REQUEST*************************/
                    struct packet res_mod;
                    manage_modify(received, res_mod);
                    //Send res to the client
                    send(res_mod);
                    break;
                }
                default:
                    break;
            }
    }

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
    }

    void manage_synch (struct packet& req, struct packet& res){
        std::map <std::string, std::string> current_hashs;
        std::map <std::string, std::string>::iterator it;
        std::map <std::string, std::string> path_to_check;
        std::string aux;
        //Bisogna operare con i path assoluti e non con quelli relativi
        std::string hash;
        std::string string_folder = backup.string() + "/backup/" + req.id + "/";
        fs::path folder = string_folder;

        if(!fs::exists(folder)) {
            res.sync_res.res = false;
            res.sync_res.description = "Error: directory doesn't exist";
            return;
        }
        //The server checks if this paths are beign modified or not. The modified one wll be inserted into a vector
        //Compute the hashs of all files and folders of server

        for(auto &file : fs::recursive_directory_iterator(folder)) {
            if(fs::is_directory(file)){
                std::pair<std::string, std::string> pair = std::make_pair(fs::relative(file, folder), "\0");
                current_hashs.insert(pair);
            }
            else if(!compute_hash((fs::path &) file, hash)){
                std::cerr << "Error" << std::endl;
                res.sync_res.res = false;
                res.sync_res.description = "Error: hash failed";
                return;
            }
            else {
                current_hashs.insert(std::pair<std::string, std::string>(fs::relative(file, folder).string(), hash));
            }
        }

        //Costruisco i path assoluti partendo da quelli relativi ricevti
        /*for(it=req.sync_req.client_paths.begin();it!=req.sync_req.client_paths.end();it++){
            aux=string_folder + it->first;
            path_to_check.insert(std::pair<std::string, std::string>(aux, it->second));
        }*/

        for (it=req.sync_req.client_paths.begin(); it!=req.sync_req.client_paths.end(); it++){
            auto position = current_hashs.find(it->first);
            if(position==current_hashs.end()){//Path non presente, bisogna inserirlo nel vettore
                res.sync_res.modified_paths.push_back(it->first);
            }
            else{
                if(position->second!=it->second)//Hash diversi
                    res.sync_res.modified_paths.push_back(it->first);
            }
        }
        res.sync_res.res = true;
        res.sync_res.description = "SUCA BENE";

        /*std::cout << "Server hashes" << std::endl;
        for(auto it=current_hashs.begin(); it != current_hashs.end(); it++){
            std::cout << it->first << ", " << it->second << std::endl;
        }

        std::cout << "Client hashes" << std::endl;
        for(auto it=req.sync_req.client_paths.begin(); it != req.sync_req.client_paths.end(); it++){
            std::cout << it->first << ", " << it->second << std::endl;
        }*/
    }

    void manage_modify (struct packet& req, struct packet& res) {
        std::string back_folder = "/Users/damiano/Desktop/Backup/backup/"+req.id+"/";
        std::string temp_folder = "/Users/damiano/Desktop/Backup/temp/"+req.id+"/";
        std::string received_path = req.mod.path;
        std::string path_to_manage = back_folder + received_path;
        std::string path_to_temp = temp_folder + received_path;
        fs::path current (path_to_manage);
        fs::path temp_folder_file (path_to_temp);
        std::ifstream ifile;

        if(req.mod.op==operation::create) {
            //Create a file in the temp directory
            if(req.mod.is_directory){
                fs::create_directory(path_to_manage);
                res.res.res = true;
                res.res.description = "SUCAAAAAA22222!";
            }
            else {
                if(fs::exists(path_to_manage)){
                    std::filesystem::copy_file(path_to_manage, temp_folder_file);
                    std::filesystem::remove(path_to_manage);
                }

                std::ofstream fs(path_to_manage);
                if (!fs) {
                    std::cerr << "Cannot open the output file." << std::endl;
                    //Return error
                    if(fs::exists(temp_folder_file)){
                        std::filesystem::copy_file(temp_folder_file, path_to_manage);
                        std::filesystem::remove(temp_folder_file);
                    }
                    res.res.res = false;
                    res.res.description = "File Creation Error!";
                }

                if(req.mod.content!="\0") {//Creazione di file
                    fs << req.mod.content;
                    std::filesystem::remove(temp_folder_file);
                }

                fs.close();
            }

            std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
            std::filesystem::permissions(current, perms);
            res.res.res = true;
            res.res.description = "SUCAAAAAA!";
        }
        else if (req.mod.op==del) {
            if (fs::exists(current)) {
                if (!std::filesystem::copy_file(current, temp_folder_file)) {
                    perror("File copy failed");
                    res.res.res = false;
                    res.res.description = "File Deletion Error!";
                } else {
                    if (!std::filesystem::remove(current)) {
                        perror("File deletion failed");
                        res.res.res = false;
                        res.res.description = "File Deletion Error!";
                    } else {
                        std::cout << "File deleted successfully";
                        res.res.res = true;
                        res.res.description = "SUCAAAA";
                    }
                }
            }
            else {
                std::cout << "File deleted successfully";
                res.res.res = true;
                res.res.description = "SUCAAAA";
            }
        }
    }

    void manage_auth (struct packet& req, struct packet& res) {
        //Interrogare il db e vedere se l'username e la password coincidono
        sqlite3* db;
        sqlite3_stmt* result;
        std::string query;
        if(sqlite3_open("/Users/damiano/Documents/GitHub/m1_backup/Server/users.db", &db) == 0) {
            query = "SELECT Password FROM utenti WHERE ID=?";
            sqlite3_prepare( db, query.c_str(), -1, &result, NULL);
            sqlite3_bind_text(result, 1, req.id.c_str(), req.id.length(), SQLITE_TRANSIENT);
            sqlite3_step(result);
            std::string password_db = reinterpret_cast<const char *>(sqlite3_column_text(result, 0));
            std::string password_user = compute_pass_hash (req.auth.password);
            int out = password_db.compare(password_user);
            if(out ==0){
                //Digests are equal
                //Set auth_response with successfull state
                res.res.description="Authentication ok";
                res.res.res=true;
            } else{
                //Digests are different
                //Set auth_response with error state
                res.res.description="Authentication failed";
                res.res.res=false;
            }
        } else{
            //Error on executing query
        }
        sqlite3_finalize(result); //Clean up function
        //sqlite3_close(db);
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

    void callback(char str[]){
        std::cout << str << std::endl;
    }
};

class Server{
public:
    Server(boost::asio::io_context& io_context) : acceptor(io_context, tcp::endpoint(tcp::v4(), 9999)),
                                                  ssl_context(boost::asio::ssl::context::tlsv12){

        ssl_context.set_options(boost::asio::ssl::context::default_workarounds
                                | boost::asio::ssl::context::no_sslv2
                                | boost::asio::ssl::context::single_dh_use);

        ssl_context.set_password_callback(std::bind(&Server::get_password, this));
        ssl_context.use_certificate_chain_file("/Users/damiano/Documents/GitHub/m1_backup/Server/myCA.pem");
        ssl_context.use_private_key_file("/Users/damiano/Documents/GitHub/m1_backup/Server/myCa.key", boost::asio::ssl::context::pem);
        ssl_context.use_tmp_dh_file("/Users/damiano/Documents/GitHub/m1_backup/Server/dh2048.pem");

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
                std::make_shared<session>(std::move(socket), ssl_context)->start();
                accept();
            }
        });
    }
};


int main() {

    boost::asio::io_context io_context;

    Server server (io_context);

    //THREAD POOL
    std::vector<std::thread> threads;

    //NUMBER OF CORE
    int core_number = std::thread::hardware_concurrency();
    std::cout<<core_number<<std::endl;

    //CREATE THREADS
    for(int i=0;i<core_number-1;i++){
        threads.push_back(std::thread([&io_context](){io_context.run();}));
    }

    /********CLIENT SENDS AUTH PACKET**************/
    struct packet req;
    req.packet_type=auth_request;
    req.id="21908767";
    req.auth.password="password1";
    /**********************************************/
    /*******************SERVER********************/

    //std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    //TERMINATE THREADS
    for(int i=0;i<core_number-1;i++){
        threads[i].join();
    }

}
