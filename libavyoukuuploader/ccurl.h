#pragma once

#include <curl/curl.h>
#include <string>
#include <list>

#define CURL_MAX_RETRY_COUNT    3

class CCurl
{
public:
    CCurl(bool use_ssl=true);
    ~CCurl();

public:
    std::string curl_send_request(const std::string& url,const void* body=NULL,size_t bodylen=0,bool breset=false);
    CURLcode    curl_get_errcode();

private:
    CURL*                      curl_;
    std::string                sPtr_;

protected:
    static size_t write_memcb_(void *contents, size_t size, size_t nmemb, void *userp);

private:
    long          timeout_;
    CURLcode      curl_code_;
};

