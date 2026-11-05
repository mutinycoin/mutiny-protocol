#ifndef BUILD8_WORKER_SOCKET_IO_V2_H
#define BUILD8_WORKER_SOCKET_IO_V2_H
#include <stddef.h>
#include <stdint.h>
/* Single owner of an already-connected, NONBLOCKING stream socket. No DNS,
 * connect, retry, credentials or authority are inferred by this adapter.
 * Socket peer identity is established only by the Worker V2 handshake.
 * fd stays owned by caller. Do not close/reassign it while a callback runs.
 * A failed callback requires stream/runtime close BEFORE descriptor close. */
typedef struct {int fd;} build8_worker_socket_io_v2;
/* Writes fd=-1 on failure. Does not close or mutate descriptor flags. */
int build8_worker_socket_io_v2_init(build8_worker_socket_io_v2 *,int);
/* worker_stream_v2 callback convention; <=1024 bytes, no internal retry. */
int build8_worker_socket_io_v2_read(void *,uint8_t *,size_t);
int build8_worker_socket_io_v2_write(void *,const uint8_t *,size_t);
#endif
