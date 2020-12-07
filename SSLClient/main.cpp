#include <iostream>
#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>

#include <openssl/ssl.h>

struct Message {
    std::string a;
    std::string b;
    std::map<std::string,int> map;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & a;
        ar & b;
    }
};

using boost::asio::ip::tcp;

const std::string delimiter = "\r\n\r\n";

class client {
public:
    client(boost::asio::io_context& io_context, boost::asio::ssl::context& ssl_context, const tcp::resolver::results_type& endpoints) : ssl_socket(io_context, ssl_context) {
        ssl_socket.set_verify_mode(boost::asio::ssl::verify_peer);
        ssl_socket.set_verify_callback(
                std::bind(&client::verify_certificate, this, std::placeholders::_1, std::placeholders::_2));

        connect(endpoints);
    }

private:
    boost::asio::ssl::stream<tcp::socket> ssl_socket;

    bool verify_certificate(bool preverified,
                            boost::asio::ssl::verify_context& ctx)
    {
        // In this example we will simply print the certificate's subject name.
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        std::cout << "Verificato: " << subject_name << "\n";

        return preverified;
    }


    void connect(const tcp::resolver::results_type& endpoints){
        boost::system::error_code error;
        boost::asio::connect(ssl_socket.lowest_layer(), endpoints ,error);

        if(!error){
            handshake();
        }
        else {
            std::cout << "Connection failed: " << error.message() << "\n";
        }
    }

    void handshake(){
        boost::system::error_code error;
        ssl_socket.handshake(boost::asio::ssl::stream_base::client, error);

        if (!error){
            send();
        }
        else {
            std::cout << "Handshake failed: " << error.message() << "\n";
        }
    }

    void send(){
            boost::system::error_code error;

            Message msg;
            msg.a = "hello";
            msg.b = "world";

            boost::asio::streambuf buf;
            std::ostream os(&buf);
            boost::archive::text_oarchive ar(os);
            ar & msg;

            const size_t header = buf.size();
            std::cout << "buffer size " << header << " bytes" << std::endl;

            // send header and buffer using scatter
            std::vector<boost::asio::const_buffer> buffers;
            buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
            buffers.push_back(buf.data());

            const size_t rc = boost::asio::write(ssl_socket, buffers, error);
            if (!error) {
                //response();
            } else {
                std::cout << "Write failed: " << error.message() << "\n";
            };

            std::cout << "wrote " << rc << " bytes\n" << std::endl;

        //boost::asio::write(ssl_socket, boost::asio::buffer("ciao" + delimiter), error);
    }
};

int main() {
    boost::asio::io_context io_context;
    boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv13);
    ssl_ctx.load_verify_file("/Users/damiano/Documents/Clion/SSLServer/myCA.pem");
    //ssl_ctx.load_verify_file("ca.pem");

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve("localhost", "9999");

    while (true) {
        client c(io_context, ssl_ctx, endpoints);
        usleep(3000000);
    }

    return 0;
}
