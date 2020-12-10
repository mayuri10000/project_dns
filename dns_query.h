//
// dns_query.h -- Contains definition of DNS packet and query related functions
// Created by liu on 5/27/20.
//

#ifndef PROJECT_DNS_DNS_QUERY_H
#define PROJECT_DNS_DNS_QUERY_H

#include "dns_common.h"
#include "dns_io.h"

/**
 * Creates a DNS request packet
 * @param name The name to be queried
 * @param type The type to be queried
 * @return The constructed DNS packet
 */
dns_packet_t DNS_query_create_request(char* name, int type);

// The following functions are server-only, and will be excluded when compiling client
#ifndef CLIENT

/**
 * Create failing response packet with specified return code
 * @param rcode The return code from server
 * @return The constructed poacket
 */
dns_packet_t DNS_query_create_fail_response(int rcode);

/**
 * Sets the current database table name to be queried, should be called before server starts
 * @param name The table name, should be the same as the server mode name
 */
void DNS_query_set_table_name(const char* name);

/**
 * Process the queries in the request packet and create
 * the DNS response packet according to the result.
 * @param request The request packet
 * @return The response packet
 */
dns_packet_t DNS_query_create_response(dns_packet_t request);

/**
 * Process the queries in the request packet and create
 * the DNS response packet according to the result.
 * Used in local server, cache will be looked up and iterative
 * queries might be made to other servers.
 * @param request The request packet
 * @return The response packet
 */
dns_packet_t DNS_query_create_response_local(dns_packet_t request);
#endif

#endif //PROJECT_DNS_DNS_QUERY_H
