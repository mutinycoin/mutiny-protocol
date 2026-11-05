#include "worker_socket_io_v2.h"
#include "lwip/sockets.h"
#include <fcntl.h>
#include <errno.h>
int build8_worker_socket_io_v2_init(build8_worker_socket_io_v2 *s,int fd){
    if(!s)return 0;
    s->fd=-1;
    if(fd<0)return 0;
    int flags=fcntl(fd,F_GETFL,0),type=0;socklen_t n=sizeof type;
    if(flags<0||!(flags&O_NONBLOCK)||getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)<0
        ||n!=sizeof type||type!=SOCK_STREAM)return 0;
    struct sockaddr_storage peer;socklen_t peer_n=sizeof peer;
    if(getpeername(fd,(struct sockaddr *)&peer,&peer_n)<0)return 0;
    s->fd=fd;return 1;
}
static int result(int n){
    if(n>0)return n;
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    return -1;
}
int build8_worker_socket_io_v2_read(void *arg,uint8_t *out,size_t n){
    build8_worker_socket_io_v2 *s=arg;
    if(!s||s->fd<0||!out||!n||n>1024)return -1;
    return result(recv(s->fd,out,n,MSG_DONTWAIT));
}
int build8_worker_socket_io_v2_write(void *arg,const uint8_t *in,size_t n){
    build8_worker_socket_io_v2 *s=arg;
    if(!s||s->fd<0||!in||!n||n>1024)return -1;
    /* lwIP has no SIGPIPE. Host qualification suppresses it explicitly. */
    int flags=MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
    flags|=MSG_NOSIGNAL;
#endif
    return result(send(s->fd,in,n,flags));
}
