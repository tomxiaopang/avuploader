#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <libYoukuUpload.h>

using namespace std;

void pcb(const UploadingTask &pTask,const std::vector< boost::shared_ptr<UploadingTask> > task_list)
{
    printf ("task:%s\tprocess:%.2f\tstat:%d\n",pTask.filename.c_str(),pTask.progress,pTask.state);
}

unsigned int test_func(int id)
{
	boost::thread::sleep(boost::get_system_time() + boost::posix_time::seconds(5));
    libYoukuUpload::get()->delete_task(id);
    return 0;
}

unsigned int input_func()
{

    std::string str;
    while(true)
    {
        cin >> str;
        if(str=="q")
        {
            exit(0);
        }
        else if(str=="help" || str =="?")
        {
            cout << "q    --  quit system"		<< endl;
        }
        else
        {
            //ErrDetail err;
            //libYoukuUpload::get()->start_task(libYoukuUpload::get()->add_upload(pInfo->token,pInfo->refresh,str.c_str(),"myUpload",err));
        }
    }
    return 0;
}

int main(int argc, char * argv[])
{
    ErrDetail err={0};

    std::vector< UploadingTaskPtr> & lstTask= libYoukuUpload::get()->get_tasks();

    libYoukuUpload::get()->set_callback(pcb);

    AccountInfo ai=libYoukuUpload::get()->login("test","test",err);

    int id=0;
    if (!ai.token.empty())
    id=libYoukuUpload::get()->add_upload(ai.token,ai.refresh,"C:\\initrd.lz","myUpload");

    libYoukuUpload::get()->start_task(id);

    boost::thread(boost::bind(test_func, id));
    boost::thread(boost::bind(input_func));


	while (1)
	{
		boost::thread::sleep(boost::get_system_time() + boost::posix_time::seconds(1));
	}

    return 0;
}