#include <iostream>
#include "FileWatcher.h"
#include "ThreadGuardVector.cpp"
#include <filesystem>
#include <fstream>
#include <vector>
#include <map>
#include <openssl/sha.h>
#include <string>
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
fs::path backup = "/Users/damiano/Desktop/Backup/";
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

    int send (struct packet pack){
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
            return 0;
        }
        std::cout << "Packet send." << std::endl;
        return rc;
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
                    if(!manage_synch(received, res_synch)){
                        std::cerr << "Fase di sincronizzazione fallita" << std::endl;
                    };
                    std::cout<<res_synch.res.description<<std::endl;
                    //Send res to the client
                    std::vector<std::string>::iterator it;
                    for(it=res_synch.sync_res.modified_paths.begin(); it!=res_synch.sync_res.modified_paths.end(); it++){
                        std::cout << *it << std::endl;
                    }
                    if(!send(res_synch)){
                        std::cerr << "Errore di connessione: impossibile mandare pacchetto di sincronizzazione." << std::endl;
                    }
                    break;
                }
                case type::auth_request: {
                    struct packet res_auth;
                    if(!manage_auth(received, res_auth)){
                        std::cerr << "Fase di authenticazione fallita" << std::endl;
                    };
                    //Send res to the client
                    std::cout<<res_auth.res.description<<std::endl;
                    if(!send(res_auth)){
                        std::cerr << "Errore di connessione: impossibile mandare pacchetto di autenticazione." << std::endl;
                    }
                    break;
                }
                case type::modify_request: {
                    /***************************MODIFY REQUEST*************************/
                    struct packet res_mod;
                    if(!manage_modify(received, res_mod)){
                        std::cerr << "Modify phase failed" << std::endl;
                    }
                    //Send res to the client
                    std::cout<<res_mod.res.description<<std::endl;
                    if(!send(res_mod)){
                        std::cerr << "Errore di connessione: impossibile mandare pacchetto di modifica." << std::endl;
                    }
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

    int manage_synch (struct packet& req, struct packet& res){
        std::map <std::string, std::string> current_hashs;
        std::map <std::string, std::string>::iterator it;
        std::map <std::string, std::string> path_to_check;
        std::string aux;
        std::string hash;
        std::string string_folder = backup.string() +  req.id + "/backup/";
        fs::path folder = string_folder;

        if(!fs::exists(folder)) {
            res.sync_res.res = false;
            res.sync_res.description = "Error: directory doesn't exist";
            std::cout << "Error: directory doesn't exist" << std::endl;
            return 0;
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
                std::cout << "Error: hash failed" << std::endl;
                return 0;
            }
            else {
                current_hashs.insert(std::pair<std::string, std::string>(fs::relative(file, folder).string(), hash));
            }
        }

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

        for(auto& path : current_hashs){
            auto position = req.sync_req.client_paths.find(path.first);
            if(position == req.sync_req.client_paths.end()){
                std::filesystem::remove_all(string_folder + path.first);
            }
        }
        res.sync_res.res = true;
        res.sync_res.description = "Synchronization succsessfully";
        return 1;
        /*std::cout << "Server hashes" << std::endl;
        for(auto it=current_hashs.begin(); it != current_hashs.end(); it++){
            std::cout << it->first << ", " << it->second << std::endl;
        }

        std::cout << "Client hashes" << std::endl;
        for(auto it=req.sync_req.client_paths.begin(); it != req.sync_req.client_paths.end(); it++){
            std::cout << it->first << ", " << it->second << std::endl;
        }*/
    }

    int manage_modify (struct packet& req, struct packet& res) {
        std::string received_path = req.mod.path;
        std::string relative_path = received_path.substr(received_path.find_last_of('/') + 1, received_path.length());
        std::string back_folder = "/Users/damiano/Desktop/Backup/" + req.id + "/backup/";
        std::string temp_folder = "/Users/damiano/Desktop/Backup/" + req.id + "/temp/";
        std::string path_to_manage = back_folder + received_path;
        std::string path_to_temp = temp_folder + relative_path;
        fs::path current (path_to_manage);
        fs::path temp_folder_file (path_to_temp);
        std::ifstream ifile;

        if(req.mod.op==operation::create) {
                    //Create a file in the temp directory
                    if(req.mod.is_directory){
                        fs::create_directory(path_to_manage);
                        res.res.res = true;
                res.res.description = "Directory creata con successo!";
                return 1;
            }
            else {
                if(fs::exists(path_to_manage)){
                    if(!std::filesystem::copy_file(path_to_manage, temp_folder_file)){
                        res.res.res = false;
                        res.res.description = "Errore durante la copia verso la cartella temporanea";
                        std::cout<<"Copia fallita"<<std::endl;
                        return 0;
                    }
                    if(!std::filesystem::remove(path_to_manage)){
                        res.res.res = false;
                        res.res.description = "Errore durante la rimozione del file dalla cartella backup";
                        std::cout<<"Rimozione fallita"<<std::endl;
                        return 0;
                    }
                }
                std::ofstream fs(path_to_manage);
                if (!fs) {
                    std::cout << "Errore durante l'apertura del file" << std::endl;
                    //Return error
                    if(fs::exists(temp_folder_file)){
                        if(!std::filesystem::copy_file(temp_folder_file, path_to_manage)){
                            res.res.res = false;
                            res.res.description = "Apertura File: Errore durante la copia verso la cartella backup";
                            std::cout<<"Copia fallita"<<std::endl;
                            return 0;
                        };
                        if(!std::filesystem::remove(temp_folder_file)){
                            res.res.res = false;
                            res.res.description = "Apertura File: Errore durante la rimozione del file dalla cartella temporanea";
                            std::cout<<"Rimozione fallita."<<std::endl;
                            return 0;
                        };
                    }
                    res.res.res = false;
                    res.res.description = "Errore durante l'apertura del file";
                    return 0;
                }

                if(req.mod.content!="\0") {//Creazione di file
                    fs << req.mod.content;
                    if(fs.bad()){
                        std::cout<<"Scrittura fallita."<<std::endl;
                        res.res.res = false;
                        res.res.description = "Errore durante la scrittura del file";
                        return 0;
                    }
                }
                fs.close();
                if(fs::exists(temp_folder_file)) {
                    if(!std::filesystem::remove(temp_folder_file)){
                        res.res.res = false;
                        res.res.description = "Errore durante la rimozione del file dalla cartella temporanea";
                        std::cout<<"Rimozione fallita"<<std::endl;
                        return 0;
                    }
                }
            }

            std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
            std::filesystem::permissions(current, perms);
            res.res.res = true;
            res.res.description = "File creato con successo.";
            return 1;
        }
        else if (req.mod.op==del) {
            if (fs::is_directory(current)){
                if (fs::exists(current)) {
                    std::error_code err;
                    std::filesystem::copy(current, temp_folder_file, err);
                    if (err) {
                        std::cout<<"Errore durante la copia verso la cartella temporanea"<<std::endl;
                        res.res.res = false;
                        res.res.description = "Copia Fallita";
                        return 0;
                    } else {
                        if (!std::filesystem::remove_all(current)) {
                            std::cout<<"Rimozione fallita"<<std::endl;
                            res.res.res = false;
                            res.res.description = "Errore durante la rimozione dei file!";
                            return 0;
                        } else {
                            if(!std::filesystem::remove_all(temp_folder_file)){
                                std::cout<<"Rimozione fallita"<<std::endl;
                                res.res.res = false;
                                res.res.description = "Errore durante la rimozione dei file!";
                                return 0;
                            }
                            std::cout << "Rimozione andata a buon fine" << std::endl;
                            res.res.res = true;
                            res.res.description = "Rimozione eseguita con sucesso!";
                            return 1;
                        }
                    }
                }
                else {//???????????
                    std::cout << "File non esistente" << std::endl;
                    res.res.res = true;
                    res.res.description = "File non esistente";
                    return 1;
                }
            }
            if (fs::exists(path_to_manage)) {
                if (!std::filesystem::copy_file(current, temp_folder_file)) {
                    std::cout<<"Rimozione File: Errore durante la copia verso la cartella temporanea."<<std::endl;
                    res.res.res = false;
                    res.res.description = "Rimozione non andata a buon fine!";
                    return 0;
                } else {
                    if (!std::filesystem::remove(current)) {
                        std::cout<<"Errore durante la rimozione del file"<<std::endl;
                        res.res.res = false;
                        res.res.description = "Rimozione non andata a buon fine.";
                        return 0;
                    } else {
                        if(!std::filesystem::remove(temp_folder_file)){
                            std::cout<<"Errore durante la rimozione del file"<<std::endl;
                            res.res.res = false;
                            res.res.description = "Rimozione non andata a buon fine.";
                            return 0;
                        }
                        std::cout << "Rimozione andata a buon fine" << std::endl;
                        res.res.res = true;
                        res.res.description = "Rimozione eseguita con successo";
                        return 1;
                    }
                }
            }
            else {//???
                std::cout << "File deleted successfully" << std::endl;
                res.res.res = true;
                res.res.description = "SUCAAAA";
                return 1;
            }
        }
        else {
            std::cout << "Operation not supported." << std::endl;
            res.res.res = false;
            res.res.description = "Operation not supported.";
            return 0;
        }
    }

    int manage_auth (struct packet& req, struct packet& res) {
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
                return 1;
            } else{
                //Digests are different
                //Set auth_response with error state
                res.res.description="Authentication failed";
                res.res.res=false;
                std::cout<<"Autenticazione fallita"<<std::endl;
                return 0;
            }
        } else{
            res.res.description="Errore apertura db";
            res.res.res=false;
            std::cout<<"Errore apertura db"<<std::endl;
            return 0;
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
    ThreadGuardVector threads(io_context);

    //NUMBER OF CORE
    int core_number = std::thread::hardware_concurrency();
    std::cout<<core_number<<std::endl;
}
