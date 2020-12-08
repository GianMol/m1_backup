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
#include <boost/bind.hpp>


namespace fs = std::filesystem;
#define SIZE 1024

//global variable socket
fs::path folder = "/cygdrive/c/Users/Corrado/Desktop/ex"; //it is a global variable in order to get the subdirectories and files relative path
fs::path backup = "/cygdrive/c/Users/Corrado/Desktop/ex/backup";
std::string id ="10";

//TASK TO EXECUTE
std::queue<std::queue <struct auth_request>> tasks;
std::queue<boost::asio::ip::tcp::socket> queues; //Coda di socket

std::mutex m1;
std::condition_variable cv;
enum operation {create, del, append, end};
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
    fs::path path;
    operation op;
    std::string content;
    std::string permissions;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & path;
        ar & op;
        ar & content;
        ar & permissions;
    }
};

struct sync_request{
    std::map<fs::path, std::string> client_paths;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & client_paths;
    }
};

struct sync_response{
    std::vector<fs::path> modified_paths;
    std::string description;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & modified_paths;
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

/* -------------------- CONNECTION -------------------- */
class connection : public boost::enable_shared_from_this<connection> {
private:
    boost::asio::ip::tcp::socket socket;
    char str[1024] = {};
    size_t header;

    void execute_task() {
        while (true) {
            std::cout << "Thread in esecuzione" << std::endl;
            std::queue<struct packet> front_queue;
            boost::asio::streambuf stream;
            struct packet received;
            boost::asio::read(socket, boost::asio::buffer(&header, sizeof(header)));

            //Body is
            boost::asio::read(socket, buf.prepare(header));
            buf.commit(header);

            //Deserializzazione
            std::istream is(&buf);
            boost::archive::text_iarchive ar(is);
            ar & received;

            switch (received.packet_type) {
                /**************************SYNCH REQUEST****************************/
                case sync_request:
                    struct packet res_synch;
                    //res_synch = manage_synch(received);
                    //Send res to the client
                    //send(res_synch)
                    break;
                case auth_request:
                    struct packet res_auth;
                    //res_auth = manage_auth(received);
                    //Send res to the client
                    //send(res_auth)
                    break;
                case modify_request:
                    while (true) {
                        /***************************MODIFY REQUEST*************************/
                        boost::asio::read(socket, boost::asio::buffer(&header, sizeof(header)));

                        //Body is
                        boost::asio::read(socket, buf.prepare(header));
                        buf.commit(header);

                        //Deserializzazione
                        std::istream is(&buf);
                        boost::archive::text_iarchive ar(is);
                        ar & received;

                        front_queue.push(received);
                        if (received.mod.op == end)
                            break;
                    }
                    while (!front_queue.empty()) {
                        auto front_queue2 = front_queue.front();
                        std::cout << "ESTRAZIONE ANDATA A BUON FINE" << std::endl;
                        struct packet res_mod;
                        //res_mod = manage_modify(front_queue2);
                        //Send res to the client
                        //send(res_mod)
                    }
                    front_queue.pop();
            }
        }
    }
public:
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

    struct packet manage_synch (struct packet req){
        std::map <fs::path, std::string> current_hashs;
        std::map <fs::path, std::string>::iterator it;
        struct packet res;
        std::string hash;
        //The server checks if this paths are beign modified or not. The modified one wll be inserted into a vector
        //Compute the hashs of all files and folders of server
        for(auto &file : fs::recursive_directory_iterator(folder)) {
            if(!compute_hash((fs::path &) file, hash)){
                std::cerr << "Error" << std::endl;
                //Error;
            }
            else {
                current_hashs.insert(std::pair<fs::path, std::string>(fs::relative(file, folder), hash));
            }
        }

        for (it=req.sync_req.client_paths.begin();it!=req.sync_req.client_paths.end();it++){
            auto position = current_hashs.find(it->first);
            if(position==current_hashs.end()){//Path non presente, bisogna inserirlo nel vettore
                res.sync_res.modified_paths.push_back(it->first);
            }
            else{
                if(position->second!=it->second)//Hash diversi
                    res.sync_res.modified_paths.push_back(it->first);
            }
        }

        //Creare cartella di backup per l'utente se non già presente
        std::ifstream ifile;
        std::string back_folder = "/cygdrive/c/Users/Corrado/Desktop/ex/backup/"+req.id+"/";
        fs::path destination (back_folder);
        ifile.open(destination);
        if(!ifile) {//The directory doesn't exist yet
            fs::create_directory(destination);
        }

        //Creare cartella temporanea per l'utente se non già presente
        std::string temp_folder = "/cygdrive/c/Users/Corrado/Desktop/ex/temp/"+req.id+"/";
        fs::path destination_temp (temp_folder);
        ifile.open(destination_temp);
        if(!ifile) {//The directory doesn't exist yet
            std::cout<<"Directory temp non esistente"<<std::endl;
            fs::create_directory(destination_temp);
        } else
            std::cout<<"Directory temp già esistente"<<std::endl;

        return res;
    }

    struct packet manage_modify (struct packet req) {
        std::string back_folder = "/cygdrive/c/Users/Corrado/Desktop/ex/backup/"+req.id+"/";
        std::string temp_folder = "/cygdrive/c/Users/Corrado/Desktop/ex/temp/"+req.id+"/";
        std::string received_path = req.mod.path;
        std::string path_to_manage = back_folder + received_path;
        std::string path_to_temp = temp_folder + received_path;
        fs::path current (path_to_manage);
        fs::path temp_folder_file (path_to_temp);
        std::ifstream ifile;
        struct packet res;
        if(req.mod.op==create) {
            //Create a file in the temp directory
            std::ofstream fs(temp_folder_file);
            if (!fs) {
                std::cerr << "Cannot open the output file." << std::endl;
                //Return error
            }
            fs << req.mod.content;
            std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
            std::filesystem::permission(&current, perms);
            fs.close();
        }
        else if (req.mod.op==del) {
            if (!std::filesystem::remove(&current))
                perror("File deletion failed");
            else
                std::cout << "File deleted successfully";
        }
        else if (req.mod.op==append) {
            //Append content to file in the temp directory
            std::ofstream outfile;
            outfile.open(temp_folder_file, std::ios_base::app);
            outfile << req.mod.content;
            std::filesystem::perms perms = translate_string_to_perms(req.mod.permissions);
            std::filesystem::permission(&current, perms);
        }
        else if (req.mod.op==end) {
            //Se tutto è andato a buon fine, si può spostare il file dalla directory temporanea a quella definitiva
            if(!std::filesystem::copy_file(&temp_folder_file, &current))
                perror("File copy failed");
            else {
                if (!std::filesystem::remove(&temp_folder_file))
                    perror("File deletion failed");
                else
                    std::cout << "File deleted successfully from temp";
            }
        }
        return res;
    }

    struct packet manage_auth (struct packet req) {
        struct packet res;
        //Interrogare il db e vedere se l'username e la password coincidono
        sqlite3* db;
        sqlite3_stmt* result;
        std::string query;
        if(sqlite3_open("/cygdrive/c/Users/Corrado/Desktop/PDS_Project/m1_backup/Server/users.db", &db) == 0)
        {
            query = "SELECT Password FROM utenti WHERE ID=?";
            std::cout<<"QUERY: "<<query<<std::endl;
            sqlite3_prepare( db, query.c_str(), -1, &result, NULL);
            sqlite3_bind_text(result, 1, req.id.c_str(), req.id.length(), SQLITE_TRANSIENT);
            sqlite3_step(result);
            std::string password_db = reinterpret_cast<const char *>(sqlite3_column_text(result, 0));
            std::string password_user = compute_pass_hash (req.auth.password);
            std::cout<<"password_db: "<<password_db<<std::endl;
            std::cout<<"password_user: "<<password_user<<std::endl;
            int out = CRYPTO_memcmp(reinterpret_cast<const void*>(&password_db), reinterpret_cast<const void*> (&password_user), SHA256_DIGEST_LENGTH); //256 is digest length
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
        return res;
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

    typedef boost::shared_ptr<connection> pointer;
    explicit connection(boost::asio::io_context& io_context) : socket(io_context) {}

    void start(){
        //socket.async_receive(boost::asio::buffer(str), boost::bind(&connection::callback, this, str));

        //socket.receive(boost::asio::buffer(str));
        //std::cout << str;

        execute_task();
        //read struct packet
        //write struct packet
    }

    void callback(char str[]){
        std::cout << str << std::endl;
    }

    static pointer create(boost::asio::io_context& io_context) {
        return pointer(new connection(io_context));
    }

    tcp::socket& get_socket() {
        return socket;
    }
};

/* -------------------- SERVER -------------------- */
class Server {
public:

    explicit server(boost::asio::io_context& ctx) : context(ctx) , acceptor(context, tcp::endpoint(tcp::v4(), 9999)) {
        std::cout << "Server attivo" << std::endl;
        start();
    }

private:
    boost::asio::io_context& context;
    tcp::acceptor acceptor;

    void start(){
        connection::pointer new_connection = connection::create(context);
        acceptor.async_accept(new_connection->get_socket(), boost::bind(&Server::handle_accept, this, new_connection, boost::asio::placeholders::error));
    }

    void handle_accept(connection::pointer new_connection,  const boost::system::error_code& error){
        if (!error) {
            new_connection->start();
        }
        start();
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
        threads.push_back(std::thread(io_context.run()));
    }


    /********CLIENT SENDS SYNCH PACKET**************/
    /*
    std::map<fs::path, std::string> received_paths;
    struct packet req;
    req.sync_req.client_paths=received_paths;
    req.packet_type=synch_request;
     */
    /**********************************************/

    /********CLIENT SENDS MODIFY PACKET**************/
    /*
    struct packet req;
    fs::path ex = "/cygdrive/c/Users/Corrado/Desktop/ex/file.txt";
    req.mod.path=ex;
    req.mod.op=append;//Funziona con del, ma da errore
    req.mod.content="ciaociaociao\nciaociaociao\n";
    req.packet_type=modify_request;
    */
    /**********************************************/

    /********CLIENT SENDS AUTH PACKET**************/
    struct packet req;
    req.packet_type=auth_request;
    req.id="21908767";
    req.auth.password="password1";
    /**********************************************/
    /*******************SERVER********************/
    std::unique_lock<std::mutex> lk(m1);
    cv.wait(lk);
    cv.notify_all();

    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    //TERMINATE THREADS
    for(int i=0;i<core_number-1;i++){
        threads[i].join();
    }
    
}
