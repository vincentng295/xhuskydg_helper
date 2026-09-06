#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include <cstdlib>

// argv[0] here is expected to be "openxtun" (the subcommand name),
// argv[1] = tun_name, argv[2..] = command to exec.
int run_openxtun(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <tun_name> <xray_cmd> [args...]\n";
        return 1;
    }

    const char* tun_name = argv[1];

    int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        perror("Failed to open /dev/net/tun");
        return 1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
    
    std::strncpy(ifr.ifr_name, tun_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(tun_fd, TUNSETIFF, (void*)&ifr) < 0) {
        perror("ioctl(TUNSETIFF) failed");
        close(tun_fd);
        return 1;
    }

    std::cout << "[opentun] Successfully opened /dev/net/tun with FD: " << tun_fd 
              << " (Interface: " << ifr.ifr_name << ")\n";

    std::string fd_str = std::to_string(tun_fd);
    if (setenv("XRAY_TUN_FD", fd_str.c_str(), 1) != 0) {
        perror("Failed to setenv XRAY_TUN_FD");
        close(tun_fd);
        return 1;
    }

    int exec_argc = argc - 2;
    char** exec_args = new char*[exec_argc + 1];

    for (int i = 0; i < exec_argc; ++i) {
        exec_args[i] = argv[i + 2];
    }
    exec_args[exec_argc] = nullptr;

    execvp(exec_args[0], exec_args);

    perror("execvp failed");
    delete[] exec_args;
    close(tun_fd);
    return 1;
}