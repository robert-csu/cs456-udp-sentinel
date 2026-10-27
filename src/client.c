#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
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
    close(sockfd);
    return EXIT_SUCCESS;
}