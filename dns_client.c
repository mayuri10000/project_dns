//
// dns_client.c -- The main source file of the DNS client application.
// Created on 5/16/20.
//

#include <stddef.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns_common.h"
#include "dns_io.h"
#include "dns_network.h"

/**
 * Print out a line of Resource Record on the terminal.
 * The content varies according to the type of the RR
 * @param rr The pointer to the RR
 */
void print_RR(dns_rr_t *rr) {
    switch (rr->type) {
        case TYPE_A:
            DNS_log_info("%10s internet address = %s", rr->name, rr->data);
            break;
        case TYPE_MX:
            DNS_log_info("%10s mail exchanger = %s", rr->name, rr->data);
            break;
        case TYPE_NS:
            DNS_log_info("%10s nameserver = %s", rr->name, rr->data);
            break;
        case TYPE_CNAME:
            DNS_log_info("%10s canonical name = %s", rr->name, rr->data);
            break;
        case TYPE_PTR:
            DNS_log_info("%10s name = %s", rr->name, rr->data);
            break;
    }
}

int main(int argc, char** argv) {
    // Usage Example: dns_client www.baidu.com A
    if (argc < 3) {
        DNS_log_error("[ dns_client ] Insufficient arguments! Usage: dns_client <domain name> <type>");
        return -1;
    }

    DNS_log_info("Server:          %s", LOCAL_DNS_IP);
    DNS_log_info("Address:         %s#%d\n", LOCAL_DNS_IP, DNS_PORT);

    char name[128];
    int type = DNS_type_from_str(argv[2]);

    // The IP address in the PTR queries should be convert to format like 1.1.168.192.in-addr.arpa
    if (type == TYPE_PTR) {
        struct in_addr addr;
        addr.s_addr = htonl(inet_addr(argv[1]));      // Convert the byte sequence
        if (addr.s_addr == -1) {
            DNS_log_error("[ dns_client ] Expected IP address of PTR query but got '%s'.", argv[1]);
            return 0;
        }
        sprintf(name, "%s.in-addr.arpa", inet_ntoa(addr));
    }
    else {
        sprintf(name, "%s", argv[1]);
    }

    dns_packet_t *packet = DNS_network_send_query_tcp(LOCAL_DNS_IP, name, type);

    // some error occurred on the network
    if (packet == NULL) {
        DNS_log_error("[ dns_client ] Query failed due to error");
        return -1;
    }

    // Error returned from the server
    if (packet->header.rcode != R_NO_ERROR) {
        DNS_log_error("[ dns_client ] Query failed: %s (%d).", DNS_rcode_to_str(packet->header.rcode), packet->header.rcode);
    }
    else {
        // Prints out the resource records
        if (packet->header.answer_count != 0) {
            DNS_log_info("Answers: ");
            for (dns_rr_t *t = packet->answers; t != NULL; t = t->next) {
                print_RR(t);
            }
            DNS_log_info("");
        }

        if (packet->header.authority_count != 0) {
            DNS_log_info("Authoritative nameservers:");
            for (dns_rr_t *t = packet->authorities; t != NULL; t = t->next) {
                print_RR(t);
            }
            DNS_log_info("");
        }

        if (packet->header.additional_count != 0) {
            DNS_log_info("Additional records:");
            for (dns_rr_t *t = packet->additionals; t != NULL; t = t->next) {
                print_RR(t);
            }
            DNS_log_info("");
        }
    }

    return 0;
}