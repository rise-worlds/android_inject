#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <ioapi.h>
#include <unzip.h>
#include <cstring>
#include <thread>
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include <asio2/asio2.hpp>
#include <asio2/tcp/tcp_server.hpp>

// the byte 1    head   (1 bytes) : #
// the byte 2    length (1 bytes) : the body length
// the byte 3... body   (n bytes) : the body content
class match_role
{
public:
    explicit match_role(char c) : c_(c) {}

    // The first member of the
    // return value is an iterator marking one-past-the-end of the bytes that have
    // been consumed by the match function.This iterator is used to calculate the
    // begin parameter for any subsequent invocation of the match condition.The
    // second member of the return value is true if a match has been found, false
    // otherwise.
    template <typename Iterator>
    std::pair<Iterator, bool> operator()(Iterator begin, Iterator end) const
    {
        Iterator p = begin;
        while (p != end)
        {
            // how to convert the Iterator to char*
            [[maybe_unused]] const char *buf = &(*p);

            // eg : How to close illegal clients
            if (*p != c_)
            {
                // method 1:
                // call the session stop function directly, you need add the init function, see below.
                session_ptr_->stop();
                break;

                // method 2:
                // return the matching success here and then determine the number of bytes received
                // in the on_recv callback function, if it is 0, we close the connection in on_recv.
                // return std::pair(begin, true); // head character is not #, return and kill the client
            }

            p++;
            if (p == end)
                break;

            int length = std::uint16_t(*p); // get content length

            p += 2;
            if (p == end)
                break;

            if (end - p >= length + 2)
                return std::pair(p + length + 2, true);

            break;
        }
        return std::pair(begin, false);
    }

    // the asio2 framework will call this function immediately after the session is created,
    // you can save the session pointer into a member variable, or do something else.
    void init(std::shared_ptr<asio2::tcp_session> &session_ptr)
    {
        session_ptr_ = session_ptr;
    }

private:
    char c_;

    // note : use a shared_ptr to save the session does not cause circular reference.
    std::shared_ptr<asio2::tcp_session> session_ptr_;
};

namespace asio
{
    template <>
    struct is_match_condition<match_role> : public std::true_type
    {
    };
}

class svr_listener
{
public:
    void on_recv(std::shared_ptr<asio2::tcp_session> &session_ptr, std::string_view data)
    {
        SPDLOG_INFO("recv : {} {}", data.size(), data.data());

        // this is just a demo to show :
        // even if we force one packet data to be sent twice,
        // but the client must recvd whole packet once
        session_ptr->async_send(data.substr(0, data.size() / 2));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        session_ptr->async_send(data.substr(data.size() / 2));
    }

    void on_connect(std::shared_ptr<asio2::tcp_session> &session_ptr)
    {
        session_ptr->no_delay(true);

        SPDLOG_INFO("client enter : {} {} {} {}",
               session_ptr->remote_address(), session_ptr->remote_port(),
               session_ptr->local_address(), session_ptr->local_port());
    }

    void on_disconnect(std::shared_ptr<asio2::tcp_session> &session_ptr)
    {
        SPDLOG_INFO("client leave : {} {} {}",
               session_ptr->remote_address(), session_ptr->remote_port(),
               asio2::last_error_msg());
    }

    void on_start(asio2::tcp_server &server)
    {
        SPDLOG_INFO("start tcp server character : {} {} {} {}",
               server.listen_address(), server.listen_port(),
               asio2::last_error_val(), asio2::last_error_msg());
    }

    void on_stop(asio2::tcp_server &server)
    {
        SPDLOG_INFO("stop tcp server character : {} {} {} {}",
               server.listen_address(), server.listen_port(),
               asio2::last_error_val(), asio2::last_error_msg());
    }
};

bool CheckUnity(const char *zipFilePath)
{
    bool find = false;
    // 1. open zip
    unzFile zipfile = unzOpen(zipFilePath);
    if (zipfile == NULL)
    {
        SPDLOG_ERROR("open zip failed , path = {}", zipFilePath);
        return find;
    }

    // 2. get global info
    unz_global_info global_info;
    if (unzGetGlobalInfo(zipfile, &global_info) != UNZ_OK)
    {
        unzClose(zipfile);
        SPDLOG_ERROR("get global info failed");
        return find;
    }

    static const char *libs_path[] = {"lib/arm64-v8a/libil2cpp.so", "lib/armeabi-v7a/libil2cpp.so", "lib/x86/libil2cpp.so", "lib/x86_64/libil2cpp.so"};
    // 3. loop files
    for (uLong i = 0; i < global_info.number_entry; ++i)
    {
        unz_file_info64 file_info64;
        char filename[1024] = {0};

        unzGetCurrentFileInfo64(zipfile, &file_info64, filename, sizeof(filename), NULL, 0, NULL, 0);
        unzCloseCurrentFile(zipfile);

        SPDLOG_DEBUG("get file: {}", filename);
        for (auto &&path : libs_path)
        {
            if (std::strstr(filename, path) == filename)
            {
                find = true;
                break;
            }
        }

        if (find || ((i + 1) < global_info.number_entry && unzGoToNextFile(zipfile) != UNZ_OK))
        {
            break;
        }
    }

    // 4. close zip file
    unzClose(zipfile);

    return find;
}

int main(int argv, const char **args)
{
    // bool result = CheckUnity(args[1]);

    // SPDLOG_INFO("currect apk is {} app", result ? "Unity 3D" : "not Unity 3D");

    asio2::tcp_server server;
    svr_listener listener;

    // bind member function
    server
        .bind_recv(&svr_listener::on_recv, listener)        // by reference
        .bind_connect(&svr_listener::on_connect, &listener) // by pointer
        .bind_disconnect(&svr_listener::on_disconnect, &listener)
        .bind_start(std::bind(&svr_listener::on_start, &listener, std::ref(server))) //     use std::bind
        .bind_stop(&svr_listener::on_stop, listener, std::ref(server));              // not use std::bind

    // Split data with string
    server.start("0.0.0.0", 10086, match_role('#'));

    while (std::getchar() != '\n')
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

    server.stop();
}
