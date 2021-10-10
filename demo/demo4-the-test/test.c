#include <unistd.h>
#include <seccomp.h>
#include <stdio.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/filter.h>

struct sock_filter sfi[] = {
    {0x20,0x00,0x00,0x00000004},
    {0x15,0x00,0x05,0xc000003e},
    {0x20,0x00,0x00,0x00000000},
    {0x35,0x00,0x01,0x40000000},
    {0x15,0x00,0x02,0xffffffff},
    {0x15,0x01,0x00,0x0000003b},
    {0x06,0x00,0x00,0x7fff0000},
    {0x06,0x00,0x00,0x00000000}
};
struct sock_fprog sfp = {8,sfi};

int test(){
    //prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    return 0;
}

int main(){

    char *binsh = "/bin/sh";
    // prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    test();
    //prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&sfp);
    // system(binsh);
    syscall(59,binsh,0,0);

    return 0;
}