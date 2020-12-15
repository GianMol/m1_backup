#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>

struct Message {
    std::string _a;
    std::string _b;
    std::map<std::string, int> map;
    size_t header;

    template <class Archive>
    void serialize(Archive& ar, unsigned int version){
        ar & _a;
        ar & _b;
        ar & map;
    }
};

using boost::asio::ip::tcp;

/* -------------------- CONNECTION -------------------- */
class connection : public boost::enable_shared_from_this<connection> {
private:
    boost::asio::ip::tcp::socket socket;
    char str[1024] = {};
    size_t header;


public:
    typedef boost::shared_ptr<connection> pointer;
    explicit connection(boost::asio::io_context& io_context) : socket(io_context) {}

    void start(){
        //socket.async_receive(boost::asio::buffer(str), boost::bind(&connection::callback, this, str));

        //socket.receive(boost::asio::buffer(str));
        //std::cout << str;

        boost::asio::read(socket, boost::asio::buffer(&header, sizeof(header)));
        std::cout << "body is " << header << " bytes" << std::endl;

        // read body
        boost::asio::streambuf buf;
        const size_t rc = boost::asio::read(socket, buf.prepare(header));
        buf.commit(header);
        std::cout << "read " << rc << " bytes" << std::endl;

        // deserialize
        std::istream is(&buf);
        boost::archive::text_iarchive ar(is);
        Message msg;
        ar & msg;

        std::cout << msg._a << std::endl;
        std::cout << msg._b << std::endl;
        std::map<std::string, int>::iterator it;
        for (it = msg.map.begin(); it != msg.map.end(); it++) {
            std::cout << it->first << " + " << it->second << std::endl;
        }
        std::cout << std::endl;

        boost::asio::write(socket, boost::asio::buffer())

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
class server {
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
        acceptor.async_accept(new_connection->get_socket(), boost::bind(&server::handle_accept, this, new_connection, boost::asio::placeholders::error));
    }

    void handle_accept(connection::pointer new_connection,  const boost::system::error_code& error){
        if (!error) {
            new_connection->start();
        }
        start();
    }
};

int main() {
    boost::asio::io_context context;
    server s(context);
    context.run();
    return 0;
}
