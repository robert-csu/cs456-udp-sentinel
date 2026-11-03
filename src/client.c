#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include "protocol.h"

int main(void)
{
    int sockfd;
    char packet[MAX_PKT_SIZE];
    int packet_len;

    // IPv4, UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
        perror("socket");
        return(EXIT_FAILURE);
    }

    //time out for UDP responses
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(sockfd);
        return(EXIT_FAILURE);
    }

    // Destination Address
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PKT_PORT);

    if (inet_pton(AF_INET, HOST, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid server IP address: %s\n", HOST);
        close(sockfd);
        return(EXIT_FAILURE);
    }

    // Send ten test packets
    for (int seq = 1; seq <= 10; seq++){

        //Spaces cannot be in packet, defined by PKT_FMT_IN
        packet_len = snprintf( packet, sizeof(packet), PKT_FMT_OUT, HOST, 8080, seq, "Hello_from_client!");

        if (packet_len < 0 || packet_len >= (int)sizeof(packet)) {
            fprintf(stderr, "Packet formatting error or packet too large.\n");
            close(sockfd);
            return(EXIT_FAILURE);
        }

        printf("Packet prepared: %s\n", packet);

        if (sendto(sockfd, packet, (size_t)packet_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("sendto");
            close(sockfd);
            return(EXIT_FAILURE);
        }

        printf("Packet sent to Sentinel on port %d\n", PKT_PORT);

        // Wait 200 milliseconds before sending the next packet
        if (seq < 10) {
            struct timespec delay = {0, 200000000};
            nanosleep(&delay, NULL);
        }
    }

    // Query Sentinel for client state
    char query[MAX_PKT_SIZE];
    int query_len = snprintf(query, sizeof(query), QUERY_FMT_OUT, HOST);

    if (query_len < 0 || query_len >= (int)sizeof(query)) {
        fprintf(stderr, "Query formatting error or query too large.\n");
        close(sockfd);
        return(EXIT_FAILURE);
    }

    printf("\nSending query to Sentinel: %s\n", query);

    if (sendto(sockfd, query, (size_t) query_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto query");
        close(sockfd);
        return(EXIT_FAILURE);
    }

    //Waiting on sentinel
    char response[MAX_PKT_SIZE];
    ssize_t response_len = recv(sockfd, response, sizeof(response) - 1, 0);

    if (response_len < 0) {
        perror("No response from Sentinel");
    } else{
        response[response_len] = '\0';
        printf("Response from Sentinel: %s\n", response);
    }



    close(sockfd);
    return EXIT_SUCCESS;
}

