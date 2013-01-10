#include "libYoukuUpload.h"
#include "codepage.h"

libYoukuUpload::libYoukuUpload():task_id_(0)
{
#ifdef WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2),&wsa);
#endif
    ::setlocale(LC_CTYPE,"");
    load_task();
}

libYoukuUpload::~libYoukuUpload()
{
#ifdef WIN32
    WSACleanup();
#endif
}

bool libYoukuUpload::parse_json(const std::string& data,boost::property_tree::wptree &root,ErrDetail &err)
{

    if (data.empty())
    {
        err.code=UPLOAD_ERR_REQUEST_FAILD;
        return false;
    }

    std::wstringstream stream;

    std::wstring utf=codepage::utf2w(data);

    stream<<utf;

    try
    {
        boost::property_tree::read_json<boost::property_tree::wptree>(stream,root);
    }
    catch(...)
    {
        err.code=UPLOAD_ERR_JSON_PARSE_FAILD;
        err.desc=utf;
        return false;
    }

    try
    {
        boost::property_tree::wptree errinfo=root.get_child(L"error");
        err.code=errinfo.get<int>(L"code");
        err.type=errinfo.get<std::wstring>(L"type");
        err.desc=errinfo.get<std::wstring>(L"description");
        return false;
    }
    catch(...)
    {
        return true;
    }
}


int libYoukuUpload::add_upload(const std::string& token,const std::string& refresh,const std::string& filename,const std::string& title)
{
    UploadingTask& pTask=alloc_task();

    pTask.filesize=boost::filesystem::file_size(filename);

    if (pTask.filesize<=0)
        return UPLOAD_ERR_IO_ERR;

    pTask.filename=filename;
    pTask.state=STAT_INIT;
    pTask.title=title;
    pTask.login_token=token;
    pTask.refresh_token=refresh;

    return pTask.id;
}

AccountInfo libYoukuUpload::login(const std::string& username,const std::string& pwd,ErrDetail& err)
{

    std::string body = "client_id=" + std::string(YOUKU_PID) + "&client_secret=" + std::string(YOUKU_TOKEN) + "&grant_type=password" +"&username=" + username + "&password=" + pwd;

    CCurl curl;
    boost::property_tree::wptree tree;
    if (!parse_json(curl.curl_send_request(OAUTH_TOKEN_URL,body.c_str(),body.length()),tree,err))
        return ai_;

    ai_.token=codepage::w2utf(tree.get<std::wstring>(L"access_token"));
    ai_.refresh=codepage::w2utf(tree.get<std::wstring>(L"refresh_token"));
    ai_.username=username;
    ai_.password=pwd;

    return ai_;

}

UploadingTask& libYoukuUpload::find_task(int id)
{
    boost::lock_guard<boost::recursive_mutex> lk(task_lock_);
    std::vector< boost::shared_ptr<UploadingTask> >::iterator it=task_list_.begin();
    for (it; it!=task_list_.end(); it++)
    {
        UploadingTask &pTask=**it;
        if (pTask.id==id)
            return pTask;
    }

    throw (int)UPLOAD_ERR_INVALID_PARAMETER;
}

void libYoukuUpload::start_task(int id)
{
    try
    {
        start_task(find_task(id));
    }
    catch(int& ec)
    {
        return;
    }
}

void libYoukuUpload::stop_task(int id)
{
    try
    {
        stop_task(find_task(id));
    }
    catch(int& ec)
    {
        return;
    }
}

void libYoukuUpload::delete_task(int id)
{
    try
    {
        delete_task(find_task(id));
    }
    catch(int& ec)
    {
        return;
    }
}


std::vector< UploadingTaskPtr > & libYoukuUpload::get_tasks()
{
    return task_list_;
}

void libYoukuUpload::load_task()
{

    boost::property_tree::ptree tree;

    try
    {
        boost::property_tree::read_json("./tasks",tree);
    }
    catch(...)
    {
        return;
    }

    clear_task();

    boost::lock_guard<boost::recursive_mutex> lk(task_lock_);

    BOOST_FOREACH(boost::property_tree::ptree::value_type& v,tree.get_child("tasks"))
    {
        UploadingTask &task=alloc_task();

        boost::property_tree::ptree& p=v.second;

        task.filename=p.get<std::string>("filename");
        task.filesize=p.get<__int64>("filesize");
        task.progress=p.get<double>("progress");
        task.hash=p.get<std::string>("hash");
        task.login_token=p.get<std::string>("login_token");
        task.server_ip=p.get<std::string>("server_ip");
        task.title=p.get<std::string>("title");
        task.refresh_token=p.get<std::string>("refresh_token");
        task.upload_token=p.get<std::string>("upload_token");
    }

}

void libYoukuUpload::clear_task()
{
    boost::lock_guard<boost::recursive_mutex> lk(task_lock_);

    std::vector< boost::shared_ptr<UploadingTask> >::iterator it=task_list_.begin();
    for (it; it!=task_list_.end(); it++)
        release_task(**it);

    task_list_.clear();

}
void libYoukuUpload::save_task()
{

    boost::lock_guard<boost::recursive_mutex> lk(task_lock_);
    std::vector< boost::shared_ptr<UploadingTask> >::iterator it=task_list_.begin();

    boost::property_tree::ptree tree;
    boost::property_tree::ptree arr;

    for (it; it!=task_list_.end(); it++)
    {
        UploadingTask& task=**it;

        boost::property_tree::ptree child;

        child.put("hash",task.hash);
        child.put("filename",task.filename);
        child.put("login_token",task.login_token);
        child.put("progress",task.progress);
        child.put("server_ip",task.server_ip);
        child.put("title",task.title);
        child.put("upload_token",task.upload_token);
        child.put("refresh_token",task.refresh_token);
        child.put("filesize",task.filesize);

        arr.push_back(std::make_pair("", child));

    }

    tree.put_child("tasks",arr);

    boost::property_tree::write_json("./tasks",tree);

}

void libYoukuUpload::stop_task(UploadingTask& task)
{

    boost::lock_guard<boost::recursive_mutex> lk(*task.mutex_ptr);

    if ( (task.state == STAT_PROCESSING ) || (task.state == STAT_STOP)
            || (task.state == STAT_ERROR) || (task.state == STAT_FINISH)
            || (task.state == STAT_DELETE))
        return;

    if ( (task.state==STAT_UPLOADING) || (task.state==STAT_HASHING) )
    {
        task.stop_flag=true;
        task.state =STAT_PROCESSING;
    }

}

void libYoukuUpload::delete_task(UploadingTask& task)
{
    boost::lock_guard<boost::recursive_mutex> lk(*task.mutex_ptr);

    if (task.state == STAT_PROCESSING )
        return;

    if ( (task.state == STAT_STOP) || (task.state == STAT_ERROR) || (task.state == STAT_DELETE) || (task.state == STAT_INIT) )
    {
        boost::lock_guard<boost::recursive_mutex> lk(task_lock_);
        heart_beat(task);
        upload_cancel(task);
        release_task(task);
        return;
    }

    if ( (task.state==STAT_UPLOADING) || (task.state==STAT_HASHING) )
    {
        task.remove_flag=true;
        task.state=STAT_PROCESSING;
    }

}

void libYoukuUpload::clean_task(UploadingTask& task)
{
    boost::lock_guard<boost::recursive_mutex> lk(*task.mutex_ptr);
    task.per_sec_speed=0;
    task.progress=0;
    task.ref=0;
    task.state=STAT_INIT;
    task.remove_flag=false;
    task.stop_flag=false;
    task.filesize=0;
    task.filename="";
    task.hash="";
    task.login_token="";
    task.refresh_token="";
    task.server_ip="";
    task.title="";
    task.upload_token="";
    task.video_id="";
    task.err.code=0;
    task.err.desc=L"";
    task.err.type=L"";
}

UploadingTask& libYoukuUpload::alloc_task()
{
    boost::shared_ptr<UploadingTask> task;
    if (!free_task_list_.empty())
    {
        boost::lock_guard<boost::recursive_mutex> lk(free_task_lock_);
        if (!free_task_list_.empty())
        {
            task=*(free_task_list_.begin());
            free_task_list_.erase(free_task_list_.begin());
        }
    } else
    {
        task.reset(new UploadingTask());
        task->mutex_ptr.reset(new boost::recursive_mutex);
        task->id=++task_id_;
        clean_task(*task);
    }
    boost::lock_guard<boost::recursive_mutex> lk(task_lock_);
    task_list_.push_back(task);
    return *task;
}

void libYoukuUpload::release_task(UploadingTask &pTask)
{
    boost::shared_ptr<UploadingTask> task;
    bool bFound=false;
    task_lock_.lock();
    std::vector< boost::shared_ptr<UploadingTask> >::iterator it=task_list_.begin();
    while (it!=task_list_.end())
    {
        task=*it;
        if (task->id==pTask.id)
        {
            bFound=true;
            task_list_.erase(it);
            break;
        }
        ++it;
    }
    save_task();
    task_lock_.unlock();

    if (bFound)
    {
        clean_task(pTask);
        boost::lock_guard<boost::recursive_mutex> lk(free_task_lock_);
        free_task_list_.push_back(task);
    }
}

void libYoukuUpload::start_task(UploadingTask& task)
{
    boost::thread td(boost::bind(&start_thread,boost::ref(task)));
}

std::string libYoukuUpload::check_md5(const std::string& file,UploadingTask& task)
{

    task.filesize=boost::filesystem::file_size(file);
    if (task.filesize<=0)
        return "";

    std::fstream iofile(file.c_str(),std::ios_base::in|std::ios_base::binary);

    unsigned char md5[16];
    MD5_CTX ctx;
    MD5_Init(&ctx);

    __int64  total_read=0;

    do
    {
        boost::lock_guard<boost::recursive_mutex> lk(*task.mutex_ptr);

        if ( task.state!=STAT_HASHING )
        {
            iofile.close();
            return "";
        }

        std::vector<char> buf;

        __int64 next_read=task.filesize<=READ_BUFF?task.filesize:READ_BUFF;

        buf.resize(next_read);

        iofile.read(&buf[0],next_read);

        if (iofile.fail())
        {
            iofile.close();
            return "";
        }

        MD5_Update(&ctx,&buf[0],next_read);
        total_read+=next_read;
        task.progress=((double)total_read/task.filesize)*100.0;
        boost::lock_guard<boost::recursive_mutex> lock(task_lock_);
        heart_beat(task);

    } while (total_read<task.filesize);

    MD5_Final(md5,&ctx);

    iofile.close();

    char tmp[3]= {0};
    for (int i=0; i<16; i++)
    {
        sprintf(tmp,"%02X",md5[i]);
        task.hash.append(tmp);
    }

    return task.hash;
}

std::string libYoukuUpload::host2ip(const std::string& host)
{
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver  resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(),host,"80");
    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query,ec);
    return !ec?endpoint_iterator->endpoint().address().to_string():"";
}

int libYoukuUpload::upload_create(UploadingTask& task)
{
    std::string body;
    body="access_token="+task.login_token;
    body.append("&client_id="+(std::string)YOUKU_PID);
    body.append("&title="+task.title);
    body.append("&tags=libUpload");
    body.append("&public_type=all");
    body.append("&copyright_type=original");
    //body.append("&watch_password="+pTask->pwd);
    //body.append("&description="+pTask->desc));
    body.append("&file_md5="+task.hash);
    body.append("&file_name="+task.filename);
    body.append("&file_size="+boost::lexical_cast<std::string>(task.filesize));

    CCurl curl;
    boost::property_tree::wptree root;
    if (!parse_json(curl.curl_send_request(UPLOADV2_CREATE,body.c_str(),body.length()),root,task.err))
        return task.err.code;

    task.upload_token=codepage::w2utf(root.get<std::wstring>(L"upload_token"));
    std::wstring instantUpload=root.get<std::wstring>(L"instant_upload_ok");
    if (instantUpload!=L"no")
        return finish_task(task,false);

    std::wstring ip_addr=root.get<std::wstring>(L"upload_server_uri");
    if (task.server_ip.empty())
        task.server_ip=host2ip(codepage::w2utf(ip_addr));

    return !task.server_ip.empty()?UPLOAD_ERR_NO_ERR:UPLOAD_ERR_PARSE_IP_FAILD;

}

unsigned int libYoukuUpload::crc32(unsigned char const * data, size_t length)
{
    boost::crc_32_type result;
    result.process_bytes(data,length);
    return result.checksum();
}

bool libYoukuUpload::parse_uri(const char* host,std::string &host_addr,u_short& n_port,std::string &req)
{
    size_t len=strlen(host);

    if (len<7)
        return false;

    char        http_head[8]= {0};

    std::string port;

    strncpy(http_head,host,7);

    std::string str_host;
    std::string ip;

    if (_strcmpi(http_head,"http://")==0)
        str_host=host+7;
    else
        str_host=host;

    const char* p=str_host.c_str();
    if (p[str_host.length()-1]=='/')
    {
        if (str_host.rfind("/")!=str_host.find("/"))
            str_host.erase(str_host.length()-1);
    }

    int pos=(int)str_host.find(":");
    if (pos>0)
    {
        ip=str_host.substr(0,pos);
        int tail=(int)str_host.find("/");
        if (tail>0)
        {
            port=str_host.substr(pos+1,str_host.length()-(pos+1));
            int jump=(int)port.find("/");
            ip+=port.substr(jump,port.length()-(jump));
            port=port.substr(0,jump);
            str_host=ip;
        }
    } else
        port="80";

    pos=(int)str_host.rfind("/");

    if (pos>0)
    {
        req=str_host.substr(pos,str_host.length()-pos);
        str_host=str_host.substr(0,pos);
    }

    pos=(int)str_host.find("/");

    if (pos>0)
        ip=str_host.substr(0,pos);
    else
        ip=str_host;

    host_addr=str_host;

    n_port=(u_short)atoi(port.c_str());

    return true;
}

bool libYoukuUpload::socket_connect(SOCKET &sock,const char *ip,u_short port, int timeout)
{
    struct timeval time_out;
    time_out.tv_sec = timeout;
    time_out.tv_usec = 0;
    struct sockaddr_in address;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock==INVALID_SOCKET)
        return false;

    address.sin_addr.s_addr = inet_addr(ip);
    address.sin_port = htons(port);
    address.sin_family = AF_INET;

    unsigned long iMode = 1;
    ioctl(sock, FIONBIO, &iMode);

    if(connect(sock,(struct sockaddr *)&address,sizeof(address))==false)
    {
        sock=INVALID_SOCKET;
        return false;
    }

    iMode = 0;
    ioctl(sock, FIONBIO, &iMode);

    fd_set w, err;
    FD_ZERO(&w);
    FD_ZERO(&err);
    FD_SET(sock, &w);
    FD_SET(sock, &err);

    // check if the socket is ready
    select(0,0,&w,&err,&time_out);
    if(FD_ISSET(sock, &w))
        return true;
    else
    {
        closesocket(sock);
        sock=INVALID_SOCKET;
        return false;
    }
}

std::string libYoukuUpload::http_request_socket(SOCKET &s,const char* host,const void* data,__int64 datalen)
{

    std::string addr,req,ip;
    u_short port;

    if (!parse_uri(host,addr,port,req))
        return "";

    ip=host2ip(addr.c_str());

    return http_request_socket(s,ip.c_str(),port,req.c_str(),data,datalen);

}

std::string libYoukuUpload::http_request_socket(SOCKET &s,const char* ip,const u_short port,const char* req,const void* data,__int64 datalen)
{

    if (s==INVALID_SOCKET)
    {
        if (!socket_connect(s,ip,port,5))
            return "";
    }
    std::string body;
    if (datalen>0)
    {
        body="POST "+(std::string)req+" HTTP/1.1\r\n";
        body+="Host: "+(std::string)ip+"\r\n";
        body+="Accept:*/*\r\n";
        body+="Agent:libYoukuUpload\r\n";
        body+="Content-Length: "+boost::lexical_cast<std::string>(datalen)+"\r\n";
        body+="Connection: keep-alive\r\n";
        body+="Content-Type: application/x-www-form-urlencoded\r\n\r\n";
    } else
    {
        body="GET "+(std::string)req+" HTTP/1.1\r\n";
        body+="Host: "+(std::string)ip+"\r\n";
        body+="Accept:*/*\r\n";
        body+="Agent:libYoukuUpload/0.1\r\n";
        body+="Connection: keep-alive\r\n\r\n";
    }

    const char* send_body= body.c_str();

    int     ret=0;
    size_t  total_sent=0;

    do
    {
        ret=send(s,send_body+total_sent,(int)(body.length()-total_sent),0);

        if (ret<0)
        {
            closesocket(s);
            s=INVALID_SOCKET;
            return "";
        }

        total_sent+=ret;

    } while (total_sent!=body.length());

    if (datalen)
    {
        total_sent=0;

        do
        {
            ret=send(s,(char*)data+total_sent,(int)(datalen-total_sent),0);

            if (ret<0)
            {
                closesocket(s);
                s=INVALID_SOCKET;
                return "";
            }

            total_sent+=ret;

        } while (total_sent!=datalen);

    }

    int         total_recv=0;
    std::string out_buf;
    int         pos=0;
    char        buf[4096]= {0};

    do
    {
        memset(&buf,0,sizeof(buf));
        int ret=recv(s,buf,sizeof(buf)-sizeof(char),0);
        if (ret<0)
        {
            closesocket(s);
            s=INVALID_SOCKET;
            return "";
        }
        total_recv+=ret;
        out_buf+=buf;

        if (ret==0)
            return out_buf;

        pos=(int)out_buf.find("\r\n\r\n");

    } while (pos<0);

    pos=(int)out_buf.find("Content-Length:");

    if (pos<0)
    {
        do
        {
            memset(&buf,0,sizeof(buf));
            int ret=recv(s,buf,sizeof(buf)-sizeof(char),0);
            if (ret<0)
            {
                closesocket(s);
                s=INVALID_SOCKET;
                return "";
            }
            total_recv+=ret;
            out_buf+=buf;

            if (ret==0)
                break;

            pos=(int)out_buf.find("Content-Length:");

        } while (pos<0);
    }


    std::string head=out_buf.substr(0,out_buf.find("\r\n\r\n")+4);

    std::string revLen;
    __int64 contentLen;

    if (pos>0)
    {
        revLen=out_buf.substr(pos+15,out_buf.find("\r\n",pos)-(pos+15));
        boost::algorithm::trim<std::string>(revLen);
        contentLen =boost::lexical_cast<__int64>(revLen);
    }
    else
    {
        revLen=out_buf.substr(out_buf.find("\r\n\r\n")+4,out_buf.length()-(out_buf.find("\r\n\r\n")+4));
        contentLen = revLen.length();
    }

    while (total_recv<contentLen+head.length())
    {
        memset(&buf,0,sizeof(buf));
        int ret=recv(s,buf,sizeof(buf)-sizeof(char),0);
        if (ret<0)
        {
            closesocket(s);
            s=INVALID_SOCKET;
            return "";
        }
        if (ret==0)
            break;

        total_recv+=ret;
        out_buf+=buf;
    }

    out_buf=out_buf.substr(out_buf.find("\r\n\r\n")+4);

    return out_buf;

}

int libYoukuUpload::upload_cancel(UploadingTask& task)
{

    if (task.upload_token.empty())
    {
        task.err.code=UPLOAD_ERR_INVALID_PARAMETER;
        return task.err.code;
    }

    std::string body;

    body="access_token="+task.login_token;
    body.append("&client_id="+(std::string)YOUKU_PID);
    body.append("&upload_token="+task.upload_token);

    std::string req=UPLOADV2_CANCEL;
    req.append("?").append(body);

    CCurl curl;
    curl.curl_send_request(req);

    return UPLOAD_ERR_NO_ERR;

}
int libYoukuUpload::upload_create_file(UploadingTask &task)
{
    std::string req="http://"+task.server_ip+"/gupload/create_file";
    std::string body;
    body="upload_token="+task.upload_token;
    body.append("&file_size="+boost::lexical_cast<std::string>(task.filesize));
    body.append("&ext="+boost::filesystem::extension(task.filename));
    body.append("&slice_length="+(std::string)UPLOAD_SLICE_SIZE);

    CCurl curl;
    boost::property_tree::wptree root;
    if (!parse_json(curl.curl_send_request(req,body.c_str(),body.length()),root,task.err))
        return task.err.code;
    else
        return UPLOAD_ERR_NO_ERR;

}

bool libYoukuUpload::upload_process_slice(UploadingTask& task,UploadPiece& piece,const std::string& json)
{

    boost::property_tree::wptree root;
    if (!parse_json(json,root,task.err))
        return false;

    piece.taskid =root.get<unsigned __int64>(L"slice_task_id");
    piece.offset=root.get<__int64>(L"offset");
    piece.size=root.get<__int64>(L"length");
    piece.transferred=root.get<__int64>(L"transferred");

    task.mutex_ptr->lock();

    if (!task.video_id.empty())
    {
        task.mutex_ptr->unlock();
        return true;
    }

    if (task.filesize>0)
        task.progress=((double)piece.transferred/task.filesize)*100.00;

    task_lock_.lock();
    heart_beat(task);
    task_lock_.unlock();

    if (root.get<bool>(L"finished"))
    {
        if (finish_task(task)==UPLOAD_ERR_NO_ERR)
        {
            task.mutex_ptr->unlock();
            return true;
        }
        else
        {
            task.mutex_ptr->unlock();
            return false;
        }
    } else
    {
        task.mutex_ptr->unlock();
        return true;
    }

}

bool libYoukuUpload::upload_upload_slice(UploadingTask& task,UploadPiece &piece,const char* crc,const char* data,SOCKET &s)
{

    std::string req;
    req="/gupload/upload_slice?upload_token="+task.upload_token;
    req.append("&slice_task_id="+boost::lexical_cast<std::string>(piece.taskid));
    req.append("&offset="+boost::lexical_cast<std::string>(piece.offset));
    req.append("&length="+boost::lexical_cast<std::string>(piece.size));
    req.append("&crc=");
    req.append(crc);

    return upload_process_slice(task,piece,http_request_socket(s,task.server_ip.c_str(),80,req.c_str(),data,piece.size));

}


bool libYoukuUpload::upload_new_slice(UploadingTask& task,SOCKET &s,UploadPiece &piece)
{
    std::string req = "gupload/new_slice?upload_token=" + task.upload_token;

    return upload_process_slice(task,piece,http_request_socket(s,task.server_ip.c_str(),80,req.c_str(),0,0));

}

int libYoukuUpload::upload_upload_file(UploadingTask &task)
{
    bool bSlice=false;

    int net_err=0;

    SOCKET s=INVALID_SOCKET;

    std::fstream iofile(task.filename.c_str(),std::ios_base::in|std::ios_base::binary);

    UploadPiece piece= {0};

    do
    {
        task.mutex_ptr->lock();
        if (task.state!=STAT_UPLOADING)
        {
            task.mutex_ptr->unlock();
            break;
        }
        task.mutex_ptr->unlock();

        if (!bSlice)
        {
            //slice only request once
            if (!upload_new_slice(task,s,piece))
            {
                net_err++;
                bSlice=false;
                boost::this_thread::sleep(boost::posix_time::milliseconds(5*1000));
                if (net_err<NET_RETRY_COUNT)
                    continue;
                break;
            }

            task.mutex_ptr->lock();
            if (task.state==STAT_FINISH)
            {
                task.mutex_ptr->unlock();
                break;
            }
            task.mutex_ptr->unlock();

            net_err=0;

            bSlice=true;
        }

        //no slice,need wait
        if ( (piece.size==0) && (piece.transferred<task.filesize) )
        {
            closesocket(s);
            s=INVALID_SOCKET;
            bSlice=false;
            boost::this_thread::sleep(boost::posix_time::milliseconds(10*1000));
            continue;
        }

        std::vector<char> buf;
        buf.resize(piece.size);
        iofile.read(&buf[0],piece.size);
        if (iofile.fail())
            break;

        //calc crc
        char crc[32]= {0};
        unsigned int cc=crc32((const unsigned char*)&buf[0],piece.size);
        sprintf(crc,"%08x",cc);

        if (!upload_upload_slice(task,piece,crc,&buf[0],s))
        {
            net_err++;
            bSlice=false;
            boost::this_thread::sleep(boost::posix_time::milliseconds(5*1000));
            if (net_err<NET_RETRY_COUNT)
                continue;
            break;
        }

        task.mutex_ptr->lock();
        if (task.state==STAT_FINISH)
        {
            //task is finished
            task.mutex_ptr->unlock();
            break;
        }
        task.mutex_ptr->unlock();

        net_err=0;

    }
    while (true);

    if (s!=INVALID_SOCKET)
    {
        closesocket(s);
        s=INVALID_SOCKET;
    }

    iofile.close();

    return UPLOAD_ERR_NO_ERR;
}

int libYoukuUpload::finish_task(UploadingTask& task,bool postip)
{
    std::string ip;
    int sleepCount=0;
    if (!postip)
        return upload_commit(task);

    while (true)
    {
        if (upload_check(task)!=UPLOAD_ERR_NO_ERR_BUT_FINISH)
        {
            if (sleepCount>FINISH_RETRY_COUNT)
                return UPLOAD_ERR_COMMIT_FAILD;
            boost::this_thread::sleep(boost::posix_time::milliseconds(30*1000));
            sleepCount++;
            continue;
        } else
        {
            //finished
            return UPLOAD_ERR_NO_ERR;
        }
    }
}

int libYoukuUpload::upload_commit(UploadingTask& task,const std::string& commit_ip)
{
    std::string body = "access_token=" + task.login_token;
    body.append("&client_id="+(std::string)YOUKU_PID);
    body.append("&upload_token="+task.upload_token);

    if (!commit_ip.empty())
        body.append("&upload_server_ip="+commit_ip);

    CCurl curl;
    boost::property_tree::wptree root;
    if (!parse_json(curl.curl_send_request(UPLOADV2_COMMIT,body.c_str(),body.length()),root,task.err))
        return UPLOAD_ERR_COMMIT_FAILD;

    task.video_id=codepage::w2utf(root.get<std::wstring>(L"video_id"));
    task.state=STAT_FINISH;

    return UPLOAD_ERR_NO_ERR_BUT_FINISH;

}

int libYoukuUpload::upload_check(UploadingTask& task)
{
    std::string body="upload_token="+task.upload_token;
    std::string req="http://"+task.server_ip+"/gupload/check?"+body;

    CCurl curl;
    boost::property_tree::wptree root;
    if (!parse_json(curl.curl_send_request(req),root,task.err))
        return UPLOAD_ERR_REQUEST_FAILD;

    if (root.get<bool>(L"finished"))
    {
        task.progress=100.0;
        return upload_commit(task,codepage::w2utf(root.get<std::wstring>(L"upload_server_ip")));
    } else
        task.progress=root.get<int>(L"transferred_percent");

    return UPLOAD_ERR_NO_ERR;
}


void libYoukuUpload::upload_thread(UploadingTask& task)
{

    task.mutex_ptr->lock();
    task.ref++;
    task.mutex_ptr->unlock();

    libYoukuUpload::get()->upload_upload_file(task);

    task.mutex_ptr->lock();
    task.ref--;
    if (task.ref==0)
    {
        if (task.remove_flag)
        {
            task.state=STAT_DELETE;
            task.mutex_ptr->unlock();
            libYoukuUpload::get()->delete_task(task);
            return;
        }

        if (task.stop_flag)
            task.state=STAT_STOP;

        libYoukuUpload::get()->task_lock_.lock();
        libYoukuUpload::get()->heart_beat(task);
        libYoukuUpload::get()->task_lock_.unlock();

        if (!task.video_id.empty())
            libYoukuUpload::get()->release_task(task);

        task.mutex_ptr->unlock();

        libYoukuUpload::get()->save_task();
    } else
        task.mutex_ptr->unlock();

}

void libYoukuUpload::start_thread(UploadingTask& task)
{
    libYoukuUpload* pUpload=libYoukuUpload::get();

    task.mutex_ptr->lock();

    if ( (task.state==STAT_INIT) || (task.state==STAT_STOP) || (task.state==STAT_ERROR) )
    {
        task.state=STAT_HASHING;

        task.mutex_ptr->unlock();

        //md5 required
        if (task.hash.empty())
        {
            pUpload->check_md5(task.filename,task);

            task.mutex_ptr->lock();

            if (task.hash.empty())
            {
                if (task.remove_flag)
                {
                    task.state=STAT_DELETE;
                    pUpload->delete_task(task);
                    task.mutex_ptr->unlock();
                    return;
                }
                else if (task.stop_flag)
                    task.state=STAT_STOP;
                else
                    task.state=STAT_ERROR;

                boost::lock_guard<boost::recursive_mutex> lk(pUpload->task_lock_);
                pUpload->heart_beat(task);
                task.mutex_ptr->unlock();
                return;
            }

            //reset upload progress
            task.progress=0;

            pUpload->save_task();
        } else
            task.mutex_ptr->lock();

        if (task.server_ip.empty())
        {
            if ( (pUpload->upload_create(task)!=UPLOAD_ERR_NO_ERR) || (pUpload->upload_create_file(task)!=UPLOAD_ERR_NO_ERR) )
            {
                boost::lock_guard<boost::recursive_mutex> lk(pUpload->task_lock_);
                pUpload->heart_beat(task);
                pUpload->release_task(task);
                task.mutex_ptr->unlock();
                return;
            }
            pUpload->save_task();

        } else
        {
            //need more check
            int ret=pUpload->upload_check(task);
            if (ret!=UPLOAD_ERR_NO_ERR)
            {
                boost::lock_guard<boost::recursive_mutex> lk(pUpload->task_lock_);
                pUpload->heart_beat(task);
                if (ret==UPLOAD_ERR_NO_ERR_BUT_FINISH)
                    pUpload->release_task(task);
                task.mutex_ptr->unlock();
                return;
            }

            pUpload->save_task();
        }

        task.state=STAT_UPLOADING;

        task.mutex_ptr->unlock();

        for (int i=0; i<UPLOAD_MAX_THREAD; i++)
            boost::thread td(boost::bind(&pUpload->upload_thread,boost::ref(task)));

    } else
        task.mutex_ptr->unlock();

}

void libYoukuUpload::set_callback(const upload_callback cb)
{
    cb_=cb;
}

void libYoukuUpload::heart_beat(const UploadingTask& task)
{
    cb_(task,task_list_);
}