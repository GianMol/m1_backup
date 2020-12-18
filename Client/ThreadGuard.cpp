#include <thread>

class ThreadGuard{
    std::thread& t;

public:
    ThreadGuard(std::thread& t_): t(t_){}

    ~ThreadGuard(){
        if(t.joinable()) t.join();
    }

    ThreadGuard(ThreadGuard const&)=delete;
    ThreadGuard& operator=(ThreadGuard const&)=delete;
};

