#include <thread>
#include <boost/asio.hpp>

class ThreadGuardVector{
    std::vector<std::thread> threads;
    boost::asio::io_context& context;

public:
    ThreadGuardVector(boost::asio::io_context& context_): context(context_){
        //NUMBER OF CORE
        for (int i = 0; i < std::thread::hardware_concurrency() - 1; ++i) {
            threads.push_back(std::thread([this](){
                context.run();
            }));
        }
    }

    ~ThreadGuardVector(){
        for(auto& thread : threads){
            thread.join();
        }
    }

    ThreadGuardVector(ThreadGuardVector const&)=delete;
    ThreadGuardVector& operator=(ThreadGuardVector const&)=delete;
};

