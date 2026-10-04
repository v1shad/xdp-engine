#ifndef LOG_TAILER_H
#define LOG_TAILER_H

#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <functional>
#include <sys/stat.h>
#include <iostream>

class LogTailer {
public:
    using LineCallback = std::function<void(const std::string&)>;

    LogTailer(std::string path, LineCallback cb)
        : path_(std::move(path)), cb_(std::move(cb)) {}

    void run(std::stop_token st) {
        std::ifstream in;
        ino_t last_inode = 0;
        dev_t last_dev = 0;
        off_t last_offset = 0;

        auto reopen_file = [&]() {
            in.close();
            in.open(path_);
            if (in.is_open()) {
                struct stat st_info;
                if (stat(path_.c_str(), &st_info) == 0) {
                    last_inode = st_info.st_ino;
                    last_dev = st_info.st_dev;
                    last_offset = 0;
                }
            }
        };

        while (!st.stop_requested()) {
            struct stat st_info;
            if (stat(path_.c_str(), &st_info) == 0) {
                if (!in.is_open()) {
                    in.open(path_);
                    if (in.is_open()) {
                        last_inode = st_info.st_ino;
                        last_dev = st_info.st_dev;
                        in.seekg(0, std::ios::end);
                        last_offset = in.tellg();
                    }
                } else {
                    if (st_info.st_ino != last_inode || st_info.st_dev != last_dev) {
                        std::cout << "[tail] rotation detected on " << path_ << "\n";
                        reopen_file();
                    } else if (st_info.st_size < last_offset) {
                        std::cout << "[tail] rotation detected on " << path_ << "\n";
                        in.clear();
                        in.seekg(0, std::ios::beg);
                        last_offset = 0;
                    }
                }
            } else {
                if (in.is_open()) {
                    in.close();
                }
            }

            if (in.is_open()) {
                std::string line;
                while (std::getline(in, line)) {
                    cb_(line);
                }
                if (in.eof()) {
                    in.clear();
                    last_offset = in.tellg();
                } else {
                    in.close();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

private:
    std::string path_;
    LineCallback cb_;
};

#endif // LOG_TAILER_H
