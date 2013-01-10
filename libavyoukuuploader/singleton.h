#pragma once
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>

template <typename T>
class Singleton
{
protected:
    Singleton(){};
    ~Singleton(){};

public:
    static T *get()
    {
        if (!ins_.get())
        {
            boost::lock_guard<boost::recursive_mutex> lock(lk_);
            if (!ins_.get())
                 ins_.reset(new T);
        }
        return ins_.get();
    }
private:
    static boost::recursive_mutex lk_;
    static boost::shared_ptr<T>   ins_;
    Singleton(const Singleton&);
    Singleton& operator=(const Singleton&);

};
template <typename T> boost::shared_ptr<T> Singleton<T>::ins_ ;
template <typename T> boost::recursive_mutex Singleton<T>::lk_;

