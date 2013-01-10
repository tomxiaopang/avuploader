#include "ccurl.h"

size_t CCurl::write_memcb_(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;

    CCurl* pCurl=(CCurl*)userp;

    pCurl->sPtr_.append((const char*)contents,realsize);

    return realsize;
}

CCurl::CCurl(bool use_ssl):curl_(0),timeout_(5),curl_code_(CURLE_OK)
{
    curl_=curl_easy_init();
    if (curl_)
    {
        if (use_ssl)
        {
            curl_easy_setopt(curl_,CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl_,CURLOPT_SSL_VERIFYHOST, 0L);
        }
    }

}

CCurl::~CCurl()
{
    if (curl_)
        curl_easy_cleanup(curl_);
}

std::string CCurl::curl_send_request(const std::string &url,const void* bd,size_t len,bool rst)
{

    int retry=CURL_MAX_RETRY_COUNT;

    if (rst)
        curl_easy_reset(curl_);

    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_memcb_);

    curl_easy_setopt(curl_, CURLOPT_WRITEDATA,this);

    curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, timeout_);

    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, timeout_);

    if ( len && bd )
    {
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, bd);
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, len);
    }

    sPtr_.clear();

    do 
    {
        curl_code_ = curl_easy_perform(curl_);
        if (curl_code_!=CURLE_OK)
        {
            retry--;
            continue;
        }else
            break;
    } while (retry);

    return sPtr_;
}

CURLcode CCurl::curl_get_errcode()
{
    return curl_code_;
}