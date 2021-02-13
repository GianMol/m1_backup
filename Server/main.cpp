#include <iostream>
#include "FileWatcher.h"
#include "Packets.h"
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
#define FILE_PATHS "/Users/damiano/Documents/GitHub/m1_backup/Support/server_paths.txt"
#define FILE_PATH_LENGTH 300

//global variables
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

//TASK TO EXECUTE
//std::queue<std::queue <struct auth_request>> tasks;
std::queue<boost::asio::ip::tcp::socket> queues; //Coda di socket


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

    void gen_random(std::string& result, const int& len) {
        unsigned char alphanum[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";
        unsigned char s [len];
        for (int i = 0; i < len; ++i) {
            s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }
        std::stringstream ss;
        for(int i = 0; i < len; i++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)s[i];
        }
        s[len] = 0;
        result = ss.str();
    }

    int send (struct response pack){
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
        struct request received;
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
                struct response res_synch;
                if(!manage_synch(received, res_synch)){
                    std::cerr << "Fase di sincronizzazione fallita" << std::endl;
                };
                std::cout<<res_synch.gen_res.description<<std::endl;
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
                struct response res_auth;
                if(!manage_auth(received, res_auth)){
                    std::cerr << "Fase di authenticazione fallita" << std::endl;
                };
                //Send res to the client
                std::cout<<res_auth.gen_res.description<<std::endl;
                if(!send(res_auth)){
                    std::cerr << "Errore di connessione: impossibile mandare pacchetto di autenticazione." << std::endl;
                }
                break;
            }
            case type::modify_request: {
                /***************************MODIFY REQUEST*************************/
                struct response res_mod;
                if(!manage_modify(received, res_mod)){
                    std::cerr << "Modify phase failed" << std::endl;
                }
                //Send res to the client
                std::cout<<res_mod.gen_res.description<<std::endl;
                if(!send(res_mod)){
                    std::cerr << "Errore di connessione: impossibile mandare pacchetto di modifica." << std::endl;
                }
                break;
            }
            case type::down_request: {
                struct response res;
                if(!manage_down(received, res)){
                    std::cerr << "Down phase failed" << std::endl;
                }
                //Send res to the client
                std::cout<<res.gen_res.description<<std::endl;
                if(!send(res)){
                    std::cerr << "Errore di connessione: impossibile mandare pacchetto di modifica." << std::endl;
                }
                break;
            }
            case type::file_request: {
                std::cout << received.file_req.path << std::endl;
                struct response res;
                if(!manage_file(received, res)){
                    std::cerr << "File Request failed" << std::endl;
                }
                //Send res to the client
                std::cout<<res.gen_res.description<<std::endl;
                if(!send(res)){
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

    int manage_synch (struct request& req, struct response& res){
        if(tokens.find(req.id)->second != req.token){
            res.sync_res.res = false;
            res.gen_res.res = false;
            res.sync_res.description = "User not authorized";
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


        if(!fs::exists(folder)) {
            res.sync_res.res = false;
            res.gen_res.res = false;
            res.sync_res.description = "Error: directory doesn't exist";
            res.gen_res.description = "Error: directory doesn't exist";
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
                res.gen_res.res = false;
                res.sync_res.description = "Error: hash failed";
                res.gen_res.description = "Error: hash failed";
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
                if(position->second!=it->second) {//Hash diversi
                    res.sync_res.modified_paths.push_back(it->first);
                }
            }
        }

        for(auto& path : current_hashs){
            auto position = req.sync_req.client_paths.find(path.first);
            if(position == req.sync_req.client_paths.end()){
                std::filesystem::remove_all(string_folder + path.first);
            }
        }
        res.sync_res.res = true;
        res.gen_res.res = true;
        res.sync_res.description = "Synchronization succsessfully";
        return 1;
    }

    int manage_modify (struct request& req, struct response& res) {
        if(tokens.find(req.id)->second != req.token){
            res.gen_res.res = false;
            res.gen_res.description = "User not authorized";
            return 0;
        }
        std::string received_path = req.mod.path;
        std::string relative_path = received_path.substr(received_path.find_last_of('/') + 1, received_path.length());
        std::string back_folder = files[4] + req.id + "/backup/";
        std::string temp_folder = files[4] + req.id + "/temp/";
        std::string path_to_manage = back_folder + received_path;
        std::string path_to_temp = temp_folder + relative_path;
        fs::path current (path_to_manage);
        fs::path temp_folder_file (path_to_temp);
        std::ifstream ifile;

        if(req.mod.op==operation::create) {
            std::cout << path_to_manage << std::endl;
            //Create a file in the temp directory
            if(req.mod.is_directory){
                std::cout << "OOOOO" << std::endl;
                fs::create_directory(path_to_manage);
                res.gen_res.res = true;
                res.gen_res.description = "Directory creata con successo!";
                return 1;
            }
            else {
                if(fs::exists(path_to_manage)){
                    if(!std::filesystem::copy_file(path_to_manage, temp_folder_file)){
                        res.gen_res.res = false;
                        res.gen_res.description = "Errore durante la copia verso la cartella temporanea";
                        std::cout<<"Copia fallita"<<std::endl;
                        return 0;
                    }
                    if(!std::filesystem::remove(path_to_manage)){
                        res.gen_res.res = false;
                        res.gen_res.description = "Errore durante la rimozione del file dalla cartella backup";
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
                            res.gen_res.res = false;
                            res.gen_res.description = "Apertura File: Errore durante la copia verso la cartella backup";
                            std::cout<<"Copia fallita"<<std::endl;
                            return 0;
                        };
                        if(!std::filesystem::remove(temp_folder_file)){
                            res.gen_res.res = false;
                            res.gen_res.description = "Apertura File: Errore durante la rimozione del file dalla cartella temporanea";
                            std::cout<<"Rimozione fallita."<<std::endl;
                            return 0;
                        };
                    }
                    res.gen_res.res = false;
                    res.gen_res.description = "Errore durante l'apertura del file";
                    return 0;
                }

                fs << req.mod.content;
                if(fs.bad()){
                    std::cout<<"Scrittura fallita."<<std::endl;
                    res.gen_res.res = false;
                    res.gen_res.description = "Errore durante la scrittura del file";
                    return 0;
                }

                fs.close();
                if(fs::exists(temp_folder_file)) {
                    if(!std::filesystem::remove(temp_folder_file)){
                        res.gen_res.res = false;
                        res.gen_res.description = "Errore durante la rimozione del file dalla cartella temporanea";
                        std::cout<<"Rimozione fallita"<<std::endl;
                        return 0;
                    }
                }
            }

            std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
            std::filesystem::permissions(current, perms);
            res.gen_res.res = true;
            res.gen_res.description = "File creato con successo.";
            return 1;
        }
        else if (req.mod.op==del) {
            if (fs::is_directory(current)){
                if (fs::exists(current)) {
                    std::error_code err;
                    std::filesystem::copy(current, temp_folder_file, err);
                    if (err) {
                        std::cout<<"Errore durante la copia verso la cartella temporanea"<<std::endl;
                        res.gen_res.res = false;
                        res.gen_res.description = "Copia Fallita";
                        return 0;
                    } else {
                        if (!std::filesystem::remove_all(current)) {
                            std::cout<<"Rimozione fallita"<<std::endl;
                            res.gen_res.res = false;
                            res.gen_res.description = "Errore durante la rimozione dei file!";
                            return 0;
                        } else {
                            if(!std::filesystem::remove_all(temp_folder_file)){
                                std::cout<<"Rimozione fallita"<<std::endl;
                                res.gen_res.res = false;
                                res.gen_res.description = "Errore durante la rimozione dei file!";
                                return 0;
                            }
                            std::cout << "Rimozione andata a buon fine" << std::endl;
                            res.gen_res.res = true;
                            res.gen_res.description = "Rimozione eseguita con sucesso!";
                            return 1;
                        }
                    }
                }
                else {//???????????
                    std::cout << "File non esistente" << std::endl;
                    res.gen_res.res = true;
                    res.gen_res.description = "File non esistente";
                    return 1;
                }
            }
            if (fs::exists(path_to_manage)) {
                if (!std::filesystem::copy_file(current, temp_folder_file)) {
                    std::cout<<"Rimozione File: Errore durante la copia verso la cartella temporanea."<<std::endl;
                    res.gen_res.res = false;
                    res.gen_res.description = "Rimozione non andata a buon fine!";
                    return 0;
                } else {
                    if (!std::filesystem::remove(current)) {
                        std::cout<<"Errore durante la rimozione del file"<<std::endl;
                        res.gen_res.res = false;
                        res.gen_res.description = "Rimozione non andata a buon fine.";
                        return 0;
                    } else {
                        if(!std::filesystem::remove(temp_folder_file)){
                            std::cout<<"Errore durante la rimozione del file"<<std::endl;
                            res.gen_res.res = false;
                            res.gen_res.description = "Rimozione non andata a buon fine.";
                            return 0;
                        }
                        std::cout << "Rimozione andata a buon fine" << std::endl;
                        res.gen_res.res = true;
                        res.gen_res.description = "Rimozione eseguita con successo";
                        return 1;
                    }
                }
            }
            else {//???
                std::cout << "File deleted successfully" << std::endl;
                res.gen_res.res = true;
                res.gen_res.description = "SUCAAAA";
                return 1;
            }
        }
        else {
            std::cout << "Operation not supported." << std::endl;
            res.gen_res.res = false;
            res.gen_res.description = "Operation not supported.";
            return 0;
        }
    }

    int manage_down (struct request& req, struct response& res) {
        if(tokens.find(req.id)->second != req.token){
            res.gen_res.res = false;
            res.gen_res.description = "User not authorized";
            return 0;
        }

        std::string directory = files[4] + req.id + "/backup/";
        std::map<std::string, std::string> all_paths;

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
                        std::cerr << "Error" << std::endl;
                        res.gen_res.res = false;
                        res.gen_res.description = "Error: hash failed";
                        std::cout << "Error: hash failed" << std::endl;
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
        res.down_res.client_paths = all_paths;
        return 1;
    }

    int manage_file (struct request& req, struct response& res) {
        std::ifstream in;
        std::string absolute_path = files[4] + req.id + "/backup/" + req.file_req.path;
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

    int manage_auth (struct request& req, struct response& res) {
        //Interrogare il db e vedere se l'username e la password coincidono
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
            if(out ==0){
                //Digests are equal
                //Set auth_response with successfull state
                res.gen_res.res=true;
                gen_random(res.token, 512);
                if(tokens.find(req.id) != tokens.end()){
                    tokens.find(req.id) -> second = res.token;
                }
                return 1;
            } else{
                //Digests are different
                //Set auth_response with error state
                res.gen_res.description="Authentication failed";
                res.gen_res.res=false;
                std::cout<<"Autenticazione fallita"<<std::endl;
                return 0;
            }
        } else{
            res.gen_res.description="Errore apertura db";
            res.gen_res.res=false;
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
        ssl_context.use_certificate_chain_file(files[0]);
        ssl_context.use_private_key_file(files[1], boost::asio::ssl::context::pem);
        ssl_context.use_tmp_dh_file(files[2]);

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

int load_certificates(){
    //std::string certificate, private_key, dh, sqlite, backup;
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

    //NUMBER OF CORE
    int core_number = std::thread::hardware_concurrency();
    std::cout<<core_number<<std::endl;
}
