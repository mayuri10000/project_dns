//
// dns_server.c -- The main source file of the DNS server application.
//                 The DNS server have 6 modes: root, local, s1, s2, s3, s4
// Created on 5/16/20.
//

#include <string.h>
#include "dns_common.h"
#include "dns_network.h"
#include "dns_query.h"

/**
 * Start the local DNS server (using the TCP protocol)
 */
void DNS_server_start_local() {
    int sock = DNS_network_init_server_socket_tcp(LOCAL_DNS_IP);
    if (sock > 0) {
        while (true) {
            DNS_network_handle_query_tcp(sock);
        }
    }
}

/**
 * Start UDP DNS server on the specified IP
 * @param ip The IP address to start the server on
 */
void DNS_server_start(const char* ip) {
    int sock = DNS_network_init_server_socket_udp(ip);
    if (sock > 0) {
        while (true) {
            DNS_network_handle_query_udp(sock);
        }
    }
}

/**
 * Main entry of the DNS server application
 * @param argc Argument count, in this application one argument is used
 * @param argv Argument values as a string array. We only use argv[1] indicating the server mode
 * @return return value of the application
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        DNS_log_error("[ dns_server ] Missing server mode argument! Usage: dns_server <mode>\n");
        return -1;
    }

    // Check server mode argument, and start the server with different configuration
    if (!strcmp(argv[1], "local")) {
        DNS_server_start_local();
    }
    else if (!strcmp(argv[1], "root")) {
        DNS_query_set_table_name("root");
        DNS_server_start(ROOT_DNS_IP);
    }
    else if (!strcmp(argv[1], "s1")) {
        DNS_query_set_table_name("s1");
        DNS_server_start(DNS_1_IP);
    }
    else if (!strcmp(argv[1], "s2")) {
        DNS_query_set_table_name("s2");
        DNS_server_start(DNS_2_IP);
    }
    else if (!strcmp(argv[1], "s3")) {
        DNS_query_set_table_name("s3");
        DNS_server_start(DNS_3_IP);
    }
    else if (!strcmp(argv[1], "s4")) {
        DNS_query_set_table_name("s4");
        DNS_server_start(DNS_4_IP);
    }
    else {
        DNS_log_error("[ dns_server ] Invalid server mode '%s', supported mode: root, local, s1, s2, s3, s4.\n", argv[1]);
        return -1;
    }
}
