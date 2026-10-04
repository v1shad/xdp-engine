#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> [args...]\n";
        return 1;
    }
    
    std::string cmd;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) cmd += " ";
        cmd += argv[i];
    }
    
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "socket error\n";
        return 1;
    }
    
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/run/xdp_engine.sock", sizeof(addr.sun_path) - 1);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "connect error (is the engine running as root?)\n";
        close(fd);
        return 1;
    }
    
    write(fd, cmd.c_str(), cmd.length());
    
    char buf[1024];
    while (true) {
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';
        std::cout << buf;
    }
    
    close(fd);
    return 0;
}
