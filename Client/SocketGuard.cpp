#include <boost/asio.hpp>

class socket_guard{
public:
    boost::asio::ip::tcp::socket socket;

    socket_guard(boost::asio::io_context& ctx): socket(ctx) {}

    socket_guard(socket_guard const&)=delete;
    socket_guard& operator=(socket_guard const&)=delete;
};
