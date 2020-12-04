#include <thread>

class thread_guard{
    std::thread& t;

public:
    thread_guard(std::thread& t_): t(t_){}

    ~thread_guard(){
        if(t.joinable()) t.join();
    }

    thread_guard(thread_guard const&)=delete;
    thread_guard& operator=(thread_guard const&)=delete;
};

