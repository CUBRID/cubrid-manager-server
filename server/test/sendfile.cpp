#include <stdio.h>
#include <string.h>
#include <signal.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <errno.h> 
#include <unistd.h> 
 
#define TRANSFER_PORT 21000

int init_transfer();
void fini_transfer();
int transfer_sock;

int init_transfer()
{
    int sock = -1;
    struct sockaddr_in addr;

    printf("init transfer бнбн/n");
    sock =  socket(PF_INET, SOCK_STREAM, 0);
    if(-1 == sock)
    {
        perror("Failed to create socket.\n");
        return -1;
    }
 
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family =   AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(TRANSFER_PORT);
    transfer_sock = sock;
    printf("%s: init transfer socket %d бнбн success\n", __FUNCTION__, sock);
    return 0;
}

void fini_transfer()
{
    int ret;
    ret = shutdown(transfer_sock, SHUT_RDWR);
    ret = close(transfer_sock);
    if(ret < 0)
        perror("fini_transfer: ");
    else
        printf("      %s: success shutdown transfer socket!\n", __FUNCTION__);
}

int send_file(int sock, const char *file_path)
{
    FILE * fp;
    char buf[1024];
    int l = 0;
    unsigned long size = 0;    
    if (file_path == NULL)
        return -1;
    
    fp = fopen(file_path, "r");
    if (fp == NULL)
        return -1;

    while ((l = fread(buf, 1, 1024, fp)) > 0)
    {
        l = send(sock, buf, l, 0);
        if(0 > l)
        {
            perror("send error: ");
            return -1;
        }
        size += l;
    }
    return size;
}

int recv_echo(int sock)
{
    char buf[1024];
    int l = 0;
  
    l = recv(sock, buf, 1024, 0);
    if(0 > l)
    {
        perror("send error: ");
        return -1;
    }     

    return l;
}

int main(int argc, char * argv[])
{
    int s;
    int len;
    struct sockaddr_in client_addr;
 
    if (argc != 3)
    {
        printf("usage : %s header_file body_file\n", argv[0]);
        return -1;
    }
 
    init_transfer();
    len = sizeof(struct sockaddr_in);
    memset(&client_addr, 0, len);
    client_addr.sin_family=AF_INET;
    client_addr.sin_port=htons(TRANSFER_PORT);
    client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    s = connect(transfer_sock, (struct sockaddr *)&client_addr, len );
    if(0 > s)
    {
        perror("connect failed!");
        fini_transfer();
        return (-1);
    }
    send_file(transfer_sock, argv[1]);
    recv_echo(transfer_sock);
    send_file(transfer_sock, argv[2]);
    recv_echo(transfer_sock);    
    fini_transfer();
    return 0;
}

