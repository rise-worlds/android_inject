#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char *argv[])
{
    printf("Victim running with PID %d\n", getpid());

    struct timeval tv = {0, 0};
    while (1)
    {
        int fd;

        fd = open("/etc/hosts", O_RDONLY);
        if (fd != -1)
            close(fd);

        fd = open("/etc/passwd", O_RDONLY);
        if (fd != -1)
            close(fd);

        int result = gettimeofday(&tv, NULL);
        printf("currect time: %ld, %d\n", tv.tv_sec, result);

        sleep(1);
    }
}