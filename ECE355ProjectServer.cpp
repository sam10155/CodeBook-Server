#include <iostream>
#include "atlstr.h"
#include <cpprest\ws_msg.h>
#include <cpprest\http_listener.h>
#include <cpprest\base_uri.h>
#include <cpprest\http_msg.h>
#include <cpprest\json.h>
#include "leveldb/db.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <algorithm>

using namespace web;
using HTTPServer       = http::experimental::listener::http_listener;
using URI              = uri;
using HTTPServerConfig = http::experimental::listener::http_listener_config;
using HTTPRequest      = http::http_request;

std::wstring ToW(std::string str)
{
    wchar_t buffer[500] = {0};
    int     length      = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, buffer, length);
    std::wstring retval = buffer;
    return retval;
}

std::string ToA(std::wstring str)
{
    char buffer[500] = {0};
    int  length      = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, buffer, length, nullptr, nullptr);
    std::string retval = buffer;
    return retval;
}

class User
{
private:
    std::string                           m_Email;
    json::value                           m_Data;
    std::chrono::system_clock::time_point m_LastInteraction;
    leveldb::DB*                          m_DB;

public:
    User()
        : m_DB(nullptr) {}
    User(leveldb::DB* DB)
        : m_DB(DB) {}
    ~User() { WriteToDB(); }
    std::string                           GetEmail();
    void                                  SetEmail(std::string);
    json::value&                          GetUserData();
    void                                  SetUserData(json::value);
    json::value                           GetSiteNames();
    leveldb::Status                       LoadFromDB(std::string email);
    void                                  WriteToDB();
    std::chrono::system_clock::time_point GetLastInteraction();
};

std::string User::GetEmail()
{
    m_LastInteraction = std::chrono::system_clock::now();
    return m_Email;
}

std::chrono::system_clock::time_point User::GetLastInteraction()
{
    return m_LastInteraction;
}

void User::SetEmail(std::string input)
{
    m_LastInteraction = std::chrono::system_clock::now();
    m_Email           = input;
}

json::value& User::GetUserData()
{
    m_LastInteraction = std::chrono::system_clock::now();
    return m_Data;
}

void User::SetUserData(json::value input)
{
    m_LastInteraction = std::chrono::system_clock::now();
    m_Data            = input;
    m_Data[L"sites"]  = json::value();
}

json::value User::GetSiteNames()
{
    json::value retValue;
    auto        array = m_Data.at(L"sites").as_object();

    auto iter  = array.begin();
    int  index = 0;

    while (iter != array.end())
    {
        retValue[index] = json::value(iter->first);
    }

    m_LastInteraction = std::chrono::system_clock::now();
    return retValue;
}

leveldb::Status User::LoadFromDB(std::string email)
{
    m_Email = email;

    std::string     value;
    leveldb::Slice  key = email;
    leveldb::Status s   = m_DB->Get(leveldb::ReadOptions(), email, &value);

    if (s.ok())
    {
        m_Data = json::value::parse(ToW(value));
    }
    m_LastInteraction = std::chrono::system_clock::now();
    return s;
}

void User::WriteToDB()
{
    auto str = m_Data.serialize();
    auto asd = ToA(m_Data.serialize());
    m_DB->Put(leveldb::WriteOptions(), m_Email, ToA(m_Data.serialize()));
}

int main()
{
    URI              url(L"http://isaacmorton.ca:1111");
    HTTPServer       Server(url);
    leveldb::DB*     db;
    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status    = leveldb::DB::Open(options, "E:\\ECE355ProjectDB", &db);
    assert(status.ok());

    std::unordered_map<std::string, User> OnlineUsers;
    std::mutex g_pages_mutex;

    auto POSTHandler = [&](HTTPRequest request) {
        //std::lock_guard<std::mutex> guard(g_pages_mutex);
        request.content_ready().wait();
        std::wcout << request.to_string() << std::endl;
        //std::wcout << request.extract_utf16string().get() << std::endl;

        std::wstring Command = request.relative_uri().to_string();
        json::value  Payload;
        try
        {
            Payload = request.extract_json(true).get();
        }
        catch (...){}

        std::string email;
        std::string pass;

        if (request.headers().find(L"Authorization") != request.headers().end())
        {
            std::wstring EncodedAuthorization = request.headers().find(L"Authorization")->second;
            BYTE         buff[500]            = {0};
            DWORD        size                 = 500;
            CryptStringToBinaryW(EncodedAuthorization.c_str(), 0, CRYPT_STRING_BASE64, buff, &size, NULL, NULL);
            std::string Authorization = reinterpret_cast<char*>(buff);
            int         colon         = Authorization.find(':');
            std::string email         = Authorization.substr(0, colon);
            std::string pass          = Authorization.substr(colon + 1, Authorization.size());

            //Load user from db or map
            User user(db);
            if (OnlineUsers.find(email) != OnlineUsers.end())
            {
                user = OnlineUsers.at(email);
            }
            else if (Command == L"/login") //load user from db if present
            {
                if (user.LoadFromDB(email).IsNotFound())
                {
                    request.reply(404).wait();
                    return;
                }

                auto str = ToA(user.GetUserData().serialize());
                OnlineUsers[email] = user;
                request.reply(200).wait();
            }
            else
            {
                request.reply(404).wait();
                return;
            }

            //authenticate user
            if (ToW(pass) != user.GetUserData().at(L"password").as_string())
            {
                request.reply(401).wait();
                return;
            }

            //commands
            if (Command == L"/login")
            {
                request.reply(200).wait();
            }
            if (Command == L"/editPassword")
            {
                std::wstring SiteName = Payload.at(L"sitename").as_string();
                std::wstring SitePassword = Payload.at(L"password").as_string();
                user.GetUserData().at(L"sites").at(SiteName).at(L"password") = json::value(SitePassword);
                request.reply(200).wait();
            }
            if (Command == L"/editUsername")
            {
                std::wstring SiteName = Payload.at(L"sitename").as_string();
                std::wstring SiteUsername = Payload.at(L"username").as_string();
                user.GetUserData().at(L"sites").at(SiteName).at(L"username") = json::value(SiteUsername);
                request.reply(200).wait();
            }
            if (Command == L"/logout")
            {
                if (OnlineUsers.find(email) != OnlineUsers.end())
                {
                    OnlineUsers.erase(email);
                }
                request.reply(200).wait();
            }
            if (Command == L"/sitenamelist")
            {
                json::value SiteName = user.GetSiteNames();
                request.reply(200, SiteName).wait();
            }
            if (Command == L"/addCombination")
            {
                std::wstring SiteName           = Payload.at(L"sitename").as_string();
                json::value& UserData           = user.GetUserData();
                UserData.at(L"sites")[SiteName] = Payload;
                request.reply(200).wait();
            }
            if (Command == L"/requestCombination")
            {
                std::wstring SiteName           = Payload.at(L"sitename").as_string();
                json::value& UserData           = user.GetUserData();
                if (UserData.at(L"sites").has_field(SiteName))
                {
                    std::wstring h = UserData.at(L"sites").at(SiteName).serialize();
                    request.reply(200, UserData.at(L"sites").at(SiteName)).wait();
                }
                else
                {
                    request.reply(404).wait();
                }
            }

            OnlineUsers[email] = user;   //write back to map
            return;
        }
        else if (Command == L"/newUser")   // new user
        {
            email = ToA(Payload.at(L"email").as_string());

            User user(db);
            user.SetEmail(email);
            user.SetUserData(Payload);
            OnlineUsers[email] = user;
            request.reply(200).wait();
            return;
        }

        request.reply(400).wait();
    };

    Server.support(POSTHandler);
    Server.open().wait();

    while (true)
    {
        //std::lock_guard<std::mutex> guard(g_pages_mutex);
        //auto iter = OnlineUsers.begin();
        //while (iter != OnlineUsers.end())
        //{
        //    if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - iter->second.GetLastInteraction()).count() >= 1000)
        //    {
        //        iter = OnlineUsers.erase(iter);
        //    }
        //    else
        //    {
        //        iter++;
        //    }
        //}
    }

    Server.close().wait();
    return 0;
}