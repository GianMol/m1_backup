#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>

#include <openssl/ssl.h>

struct Message {
    std::string a;
    std::string b;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & a;
        ar & b;
    }
};

using boost::asio::ip::tcp;

/* -------------------- SESSION -------------------- */
class session : public std::enable_shared_from_this<session> {
public:
    session(tcp::socket socket, boost::asio::ssl::context& context)
    : ssl_socket(std::move(socket), context) {}

    void start(){
        handshake();
    }

private:
    void handshake(){
        auto self(shared_from_this());
        boost::system::error_code error;
        ssl_socket.handshake(boost::asio::ssl::stream_base::server, error);

        if(!error){
            read();
        }
        else {
            std::cout << "Handshake failed: " << error.message() << "\n";
        }
    }

    void read(){
        auto self(shared_from_this());
        boost::system::error_code error;
        boost::asio::streambuf streambuf;

        boost::asio::read(ssl_socket, boost::asio::buffer(&header, sizeof(header)), error);
        if (!error){
            //write();
        }
        else {
            std::cout << "Read failed: " << error.message() << "\n";
        }


        std::cout << "body is " << header << " bytes" << std::endl;

        boost::asio::streambuf buf;
        const size_t rc = boost::asio::read(ssl_socket, buf.prepare(header), error);
        if (!error){
            buf.commit(header);
            std::cout << "read " << rc << " bytes" << std::endl;

            // deserialize
            std::istream is(&buf);
            boost::archive::text_iarchive ar(is);
            Message msg;
            ar & msg;

            std::cout << msg.a << std::endl;
            std::cout << msg.b << std::endl;
        }

        else {
            std::cout << "Read failed: " << error.message() << "\n";
        }

    }

    boost::asio::ssl::stream<tcp::socket> ssl_socket;
    char data_[1024];
    size_t header;
};

class server{
public:
    server(boost::asio::io_context& io_context) : acceptor(io_context, tcp::endpoint(tcp::v4(), 9999)),
    ssl_context(boost::asio::ssl::context::tlsv13){

        ssl_context.set_options(boost::asio::ssl::context::default_workarounds
                                | boost::asio::ssl::context::no_sslv2
                                | boost::asio::ssl::context::single_dh_use);

        ssl_context.set_password_callback(std::bind(&server::get_password, this));
        ssl_context.use_certificate_chain_file("/Users/damiano/Documents/Clion/SSLServer/myCA.pem");
        ssl_context.use_private_key_file("/Users/damiano/Documents/Clion/SSLServer/myCa.key", boost::asio::ssl::context::pem);
        ssl_context.use_tmp_dh_file("/Users/damiano/Documents/Clion/SSLServer/dh2048.pem");

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
    try
    {
        boost::asio::io_context io_context;
        server s(io_context);
        std::thread t1 = std::thread([&](){
            io_context.run();
        });
        t1.join();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}