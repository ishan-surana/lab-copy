#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define MAXLINE 4096 /* max text line length */
#define SERVPORT 3000 /* port */
#define LISTENQ 8 /* maximum number of client connections */

int main(int argc, char **argv)
{
    pid_t childpid;
    int listenfd, connfd, n;
    socklen_t clilen;
    char buf[MAXLINE];
    struct sockaddr_in cliaddr, servaddr;

    // Create a socket
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Problem in creating the socket");
        exit(2);
    }

    // Preparation of the socket address
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERVPORT);

    // Bind the socket
    bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    // Listen to the socket by creating a connection queue, then wait for
    listen(listenfd, LISTENQ);
    printf("%s\n", "Server running...waiting for connections.");

    for (;;) {
        clilen = sizeof(cliaddr);
        // Accept a connection
        connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
        printf("%s\n", "Received request...");

        if ((childpid = fork()) == 0) { // If it's 0, it's the child process
            printf("%s\n", "Child created for dealing with client requests");
            // Close listening socket
            close(listenfd);

            while ((n = recv(connfd, buf, MAXLINE, 0)) > 0) {
                printf("%s", "String received from and resent to the client: ");
                puts(buf);
                send(connfd, buf, n, 0);
            }

            if (n < 0)
                printf("%s\n", "Read error");
            exit(0);
        }
        // Close socket of the server
        close(connfd);
    }
}

