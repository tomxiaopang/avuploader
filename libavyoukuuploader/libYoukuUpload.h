#pragma once

#define  _WINVER			0x0501   //let XP as the default os platform. 
#define  _WIN32_WINDOWS		0x0501
#define  _WIN32_WINNT		0x0501

#include "singleton.h"
#include "ccurl.h"
#include "config.h"

#include <vector>
#include <string>
#ifdef WIN32
#ifdef DLLEXPORT
#define DLL _declspec(dllexport)
#else
#define DLL _declspec(dllimport)
#endif

#else
#define _FILE_OFFSET_BITS   64
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#define __stdcall
#define __int64 long long
#define SOCKET int
#define SOCKADDR_IN sockaddr_in
#define _strcmpi strcasecmp
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#define closesocket close
#endif

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <boost/crc.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/md5.h>

typedef enum TaskStat
{
    STAT_INIT=0,
    STAT_HASHING,
    STAT_UPLOADING,
    STAT_PROCESSING,
    STAT_STOP,
    STAT_ERROR,
    STAT_FINISH,
    STAT_DELETE,
    STAT_MAX=100,
} TaskStat;

struct AccountInfo
{
    std::string username;
    std::string password;
    std::string token;
    std::string refresh;
};

struct ErrDetail
{
    int          code;
    std::wstring type;
    std::wstring desc;
};

struct UploadPiece
{
	uint64_t		taskid;
    int64_t			offset;
    int64_t			size;
    int64_t			transferred;
};

struct UploadingTask
{
    int                     id;
    std::string             filename;
    __int64                 filesize;
    std::string             hash;
    std::string             server_ip;
    std::string             title;
    int                     state;
    std::string             login_token;
    std::string             upload_token;
    std::string             refresh_token;
    std::string             video_id;
    int                     per_sec_speed;
    double                  progress;
    int                     ref;
    bool                    remove_flag;
    bool                    stop_flag;
    boost::shared_ptr<boost::recursive_mutex>  mutex_ptr;
    ErrDetail               err;
    UploadingTask()
    {
        printf("create task\n");
    }
    ~UploadingTask()
    {
        printf("free task\n");
    }
};

typedef boost::shared_ptr<UploadingTask> UploadingTaskPtr;

enum UploadError
{
    UPLOAD_ERR_NO_ERR=0,
    UPLOAD_ERR_INVALID_PARAMETER=-100,
    UPLOAD_ERR_REQUEST_FAILD,
    UPLOAD_ERR_JSON_PARSE_FAILD,
    UPLOAD_ERR_IO_ERR,
    UPLOAD_ERR_COMMIT_FAILD,
    UPLOAD_ERR_PARSE_IP_FAILD,
    UPLOAD_ERR_NOT_ENOUGH_MEM,
    UPLOAD_ERR_NO_ERR_BUT_FINISH,
};

typedef boost::function<void(const UploadingTask &pTask,const std::vector<UploadingTaskPtr> task_list)> upload_callback;

#ifdef WIN32
class DLL libYoukuUpload:public Singleton<libYoukuUpload>
#else
class libYoukuUpload:public Singleton<libYoukuUpload>
#endif
{
    friend class Singleton<libYoukuUpload>;
private:
    libYoukuUpload();
public:
    ~libYoukuUpload();

public:
    AccountInfo login(const std::string& username,const std::string& pwd,ErrDetail& err);
    int         add_upload(const std::string& token,const std::string& refresh,const std::string& filename,const std::string& title);

    void start_task(int id);
    void stop_task(int id);
    void delete_task(int id);

    std::vector< UploadingTaskPtr > & get_tasks();

private:
    void           clear_task();
    void           save_task();
    void           load_task();

private:
    UploadingTask& find_task(int id);
    void           start_task(UploadingTask& task);
    void           stop_task(UploadingTask& task);
    int            finish_task(UploadingTask& task,bool postip=true);
    void           delete_task(UploadingTask& task);

private:
    UploadingTask& alloc_task();
    void           release_task(UploadingTask& pTask);
    void           clean_task(UploadingTask& pTask);

private:
    std::string    check_md5(const std::string& file,UploadingTask& task);
    std::string    host2ip(const std::string& host);

protected:
    int            upload_create(UploadingTask& task);
    int            upload_commit(UploadingTask& task,const std::string& commit_ip="");
    int            upload_check(UploadingTask& task);
    int            upload_create_file(UploadingTask& task);
    int            upload_cancel(UploadingTask& task);

protected:

    int            upload_upload_file(UploadingTask &task);
    bool           upload_new_slice(UploadingTask& task,SOCKET &s,UploadPiece &piece);
    bool           upload_upload_slice(UploadingTask& task,UploadPiece &piece,const char* crc,const char* data,SOCKET &s);

    bool           upload_process_slice(UploadingTask& task,UploadPiece& piece,const std::string& json);

private:
    bool           parse_json(const std::string& buf,boost::property_tree::wptree &root,ErrDetail &err);
    unsigned int   crc32(unsigned char const * data, size_t length);
    std::string    http_request_socket(SOCKET &sock,const char* ip,const u_short port,const char* req,const void* data,__int64 datalen);
    std::string    http_request_socket(SOCKET &sock,const char* host,const void* data,__int64 datalen);
    bool           parse_uri(const char* host,std::string &host_addr,u_short& n_port,std::string &req);
    bool           socket_connect(SOCKET &sock,const char *ip,u_short port, int timeout);

protected:
    static void upload_thread(UploadingTask &task);
    static void start_thread(UploadingTask &task);

public:
    void set_callback(const upload_callback cb);

private:
    void heart_beat(const UploadingTask& task);

private:
    boost::recursive_mutex                      task_lock_;
    boost::recursive_mutex                      free_task_lock_;

    std::vector< boost::shared_ptr<UploadingTask> > task_list_;
    std::vector< boost::shared_ptr<UploadingTask> > free_task_list_;

    upload_callback                 cb_;
    int                             task_id_;
    AccountInfo                     ai_;
};

