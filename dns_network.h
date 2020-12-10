//
// dns_network.h -- Network related functions of the DNS system
// Created on 5/27/20.
//

#ifndef PROJECT_DNS_DNS_NETWORK_H
#define PROJECT_DNS_DNS_NETWORK_H
#include "dns_io.h"

// Server-only functions, will be excluded in client
#ifndef CLIENT

/**
 * Initialize UDP socket for server
 * @param address The address to listen on
 * @return The socket
 */
int DNS_network_init_server_socket_udp(const char *address);

/**
 * Initialize TCP socket for server
 * @param address The address to listen on
 * @return The socket
 */
int DNS_network_init_server_socket_tcp(const char *address);

/**
 * Handle one single request from the client with UDP
 * @param sock The socket
 */
void DNS_network_handle_query_udp(int sock);

/**
 * Handle one single request from the client with TCP
 * @param sock The socket
 */
void DNS_network_handle_query_tcp(int sock);
#endif

/**
 * Send a DNS query to the a DNS server with UDP and retrieve the response
 * @param address The address of the server
 * @param name The name to be queried
 * @param type The query type
 * @return The response packet from server, NULL if error occurs in the query
 */
dns_packet_t *DNS_network_send_query_udp(const char* address, char* name, int type);

/**
 * Send a DNS query to the a DNS server with TCP and retrieve the response
 * @param address The address of the server
 * @param name The name to be queried
 * @param type The query type
 * @return The response packet from server, NULL if error occurs in the query
 */
dns_packet_t *DNS_network_send_query_tcp(const char* address, char* name, int type);

#endif //PROJECT_DNS_DNS_NETWORK_H
