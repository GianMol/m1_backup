#include <iostream>

#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/map.hpp>
#include <string>

#include <boost/asio.hpp>
#include <map>

#define SIZE 1024

struct Message {
    std::string _a;
    std::string _b;
    std::map<std::string,int> map;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & _a;
        ar & _b;
        ar & map;
    }
};

//char* foo = reinterpret_cast<char*>(bar);

int main(){
    Message msg;
    msg._a = "hello";
    msg._b = "world";
    msg.map.insert(std::pair<std::string, int>("ciao", 2));
    msg.map.insert(std::pair<std::string, int>("ciao3", 4));

    while (true) {

        boost::asio::streambuf buf;
        std::ostream os(&buf);
        boost::archive::text_oarchive ar(os);
        ar & msg;

        boost::asio::io_service io_service;

        // Client socket
        boost::asio::ip::tcp::socket client_socket(io_service);

        boost::system::error_code err;
        client_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 9999),
                              err);
        if (err.failed()) {
            std::cout << "Connessione non riuscita" << std::endl;
            return 0;
        }

        const size_t header = buf.size();
        std::cout << "buffer size " << header << " bytes" << std::endl;

        // send header and buffer using scatter
        std::vector<boost::asio::const_buffer> buffers;
        buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
        buffers.push_back(buf.data());

        const size_t rc = boost::asio::write(client_socket, buffers);
        std::cout << "wrote " << rc << " bytes\n" << std::endl;
        usleep(2000000);
    }
    return 0;
}
