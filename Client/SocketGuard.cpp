#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

class socket_guard{
public:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket;

    socket_guard(boost::asio::io_context& ctx, boost::asio::ssl::context& ssl_ctx): socket(ctx, ssl_ctx) {
        socket.set_verify_mode(boost::asio::ssl::verify_peer);
        socket.set_verify_callback(std::bind(&socket_guard::verify_certificate, this, std::placeholders::_1, std::placeholders::_2));
    }

    bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx){
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        return preverified;
    }

    socket_guard(socket_guard const&)=delete;
    socket_guard& operator=(socket_guard const&)=delete;
};
