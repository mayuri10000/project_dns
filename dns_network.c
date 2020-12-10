//
// dns_network.c -- Implementation of network related functions of the DNS system
// Created on 5/26/20.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "dns_common.h"
#include "dns_query.h"
#include "dns_io.h"

// The buffer size for receiving data from sockets
#define BUFFER_SIZE 1024


/**
 * Print out an RR to the terminal in the WireShark-like format
 * @param rr The Resource Record
 */
void rr_print(dns_rr_t rr) {
    char info[128];
    if (rr.type == TYPE_MX) {
        int pref;
        char name[64];
        if (sscanf(rr.data, "%d,%s", &pref, name) != 2) {
            sprintf(info, "mx %s", rr.data);
        }
        else {
            // The MX RRs contains a preference field
            sprintf(info, "preference %d, mx %s", pref, name);
        }
    }
    else if (rr.type == TYPE_A) {
        sprintf(info, "addr %s", rr.data);
    }
    else if (rr.type == TYPE_CNAME) {
        sprintf(info, "cname %s", rr.data);
    }
    else if (rr.type == TYPE_NS) {
        sprintf(info, "ns %s", rr.data);
    }
    else {
        sprintf(info, "%s", rr.data);
    }

    DNS_log_trace("      %s: type %s, class %s, %s", rr.name, DNS_type_to_str(rr.type), DNS_class_to_str(rr.class), info);
}

/**
 * Print a DNS packet info in WireShark-like format
 * @param packet The packet
 * @param addr The address of sending or receiving this packet
 * @param is_send Whether this packet is sent
 */
void packet_print(dns_packet_t packet, struct sockaddr_in addr, bool is_send) {
    if (is_send)
        DNS_log_trace("[ dns_network] Sending packet to %s:%d : ", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    else
        DNS_log_trace("[ dns_network] Received packet from %s:%d : ", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    DNS_log_trace("Domain Name System (%s)", (packet.header.qr ? "response" : "request"));
    DNS_log_trace("   Transaction ID: 0x%04x", packet.header.id);
    DNS_log_trace("   Flags: 0x%04x %s %s, %s",
                  ntohs(((uint16 *) &packet.header)[1]), DNS_opcode_to_str(packet.header.opcode),
                  (packet.header.qr ? "response" : "request"), DNS_rcode_to_str(packet.header.rcode));
    DNS_log_trace("   Questions: %d", packet.header.question_count);
    DNS_log_trace("   Answer RRs: %d", packet.header.answer_count);
    DNS_log_trace("   Authority RRs: %d", packet.header.authority_count);
    DNS_log_trace("   Additional RRs: %d", packet.header.additional_count);

    DNS_log_trace("   Queries");
    for (dns_query_t *t = packet.queries; t != NULL; t = t->next) {
        DNS_log_trace("      %s: type %s, class %s", t->name, DNS_type_to_str(t->type), DNS_class_to_str(t->class));
    }

    if (packet.header.qr) {
        if (packet.answers != NULL) {
            DNS_log_trace("   Answers");
            for (dns_rr_t *t = packet.answers; t != NULL; t = t->next) {
                rr_print(*t);
            }
        }
        if (packet.authorities != NULL) {
            DNS_log_trace("   Authoritative nameservers");
            for (dns_rr_t *t = packet.authorities; t != NULL; t = t->next) {
                rr_print(*t);
            }
        }
        if (packet.additionals != NULL) {
            DNS_log_trace("   Additional Records");
            for (dns_rr_t *t = packet.additionals; t != NULL; t = t->next) {
                rr_print(*t);
            }
        }
    }
    DNS_log_trace("[ dns_network] END of DNS packet.\n");
}

#ifndef CLIENT
// Some server-only code that we don't expect in the client

int DNS_network_init_server_socket_udp(const char *address) {
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        DNS_log_error("[ dns_network] Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = inet_addr(address);
    int bind_ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (bind_ret < 0) {
        DNS_log_error("[ dns_network] Failed to bind UDP socket to %s:%d : %s", address, DNS_PORT,
                      strerror(errno));
        return -1;
    }

    DNS_log_info("Listening on UDP port %d on %s", DNS_PORT, address);

    return sock;
}

int DNS_network_init_server_socket_tcp(const char *address) {
    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        DNS_log_error("[ dns_network] Failed to create TCP socket.");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = inet_addr(address);
    int bind_ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (bind_ret < 0) {
        DNS_log_error("[ dns_network] Failed to bind TCP socket to %s:%d : %s", address, DNS_PORT, strerror(errno));
        return -1;
    }

    int listen_ret = listen(sock, 10);
    if (listen_ret < 0) {
        DNS_log_error("[dns_network ] Failed to listen on TCP socket on %s:%d : %s", address, DNS_PORT, strerror(errno));
        close(sock);
        return -1;
    }

    DNS_log_info("Listening on TCP port %d on %s", DNS_PORT, address);

    return sock;
}

void DNS_network_handle_query_udp(int sock) {
    char buf[BUFFER_SIZE] = {0};
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);

    int ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);

    if (ret > 0) {
        buffer_t buffer = DNS_buffer_from_ptr(buf, ret);
        dns_packet_t packet;
        packet.queries = NULL;
        packet.answers = NULL;
        packet.authorities = NULL;
        packet.additionals = NULL;

        dns_packet_t send_packet;
        send_packet.queries = NULL;
        send_packet.answers = NULL;
        send_packet.authorities = NULL;
        send_packet.additionals = NULL;
        if (DNS_buffer_read_packet(buffer, &packet)) {
            packet_print(packet, peer, false);
            send_packet = DNS_query_create_response(packet);
        }
        else {
            send_packet = DNS_query_create_fail_response(R_FORMAT_ERR);
            DNS_log_error("[ dns_network] Failed to decode incoming packet as DNS packet, the length is %d", ret);
        }
        packet_print(send_packet, peer, true);
        buffer_t send_buffer = DNS_buffer_create(BUFFER_SIZE);
        DNS_buffer_write_packet(send_buffer, send_packet);

        int ret1 = sendto(sock, send_buffer->ptr, send_buffer->pos, 0, (struct sockaddr *) &peer, peer_len);
        if (ret1 < 0) {
            DNS_log_error("[ dns_network] Failed to send response to the client.");
        }

        DNS_buffer_free(send_buffer);

    } else {
        DNS_log_error("[ dns_network] Failed to receive request from client.");
    }
}

void DNS_network_handle_query_tcp(int sock) {
    char buf[BUFFER_SIZE] = {0};
    char buf_rec[BUFFER_SIZE] = {0};
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int sock2 = accept(sock, (struct sockaddr *) &peer, &peer_len);
    if (sock2 < 0) {
        DNS_log_error("[ dns_network] Failed to accept connection from the client: %s", strerror(errno));
        return;
    }

    DNS_log_trace("[ dns_network] Accepted connection from %s:%d", inet_ntoa(peer.sin_addr), htons(peer.sin_port));

    int ret = recv(sock2, buf, sizeof(buf), 0);
    if (ret > 0) {
        // The DNS packet transmitted in the TCP protocol contains a length field at the begining of the packet
        // We initialize the packet buffer just at the start of the DNS header
        buffer_t buffer = DNS_buffer_from_ptr(buf + 2, ret - 2); // Skip the length field
        dns_packet_t packet;
        packet.queries = NULL;
        packet.answers = NULL;
        packet.authorities = NULL;
        packet.additionals = NULL;

        dns_packet_t send_packet;
        send_packet.queries = NULL;
        send_packet.answers = NULL;
        send_packet.authorities = NULL;
        send_packet.additionals = NULL;
        if (DNS_buffer_read_packet(buffer, &packet)) {
            packet_print(packet, peer, false);
            send_packet = DNS_query_create_response_local(packet);
        }
        else {
            DNS_log_error("[ dns_network] Failed to decode incoming packet as DNS packet, the length is %d", ret);
            send_packet = DNS_query_create_fail_response(R_FORMAT_ERR);
        }
        packet_print(send_packet, peer, true);
        buffer_t send_buffer = DNS_buffer_from_ptr(buf_rec + 2, BUFFER_SIZE - 2);
        DNS_buffer_write_packet(send_buffer, send_packet);
        uint16 len = (uint16) send_buffer->pos;
        *((uint16 *)buf_rec) = htons(len);

        int ret1 = send(sock2, buf_rec, len + 2, 0);
        if (ret1 < 0) {
            DNS_log_error("[ dns_network] Failed to send response to the client: %s", strerror(errno));
        }

    } else {
        DNS_log_error("[ dns_network] Failed to receive request from client: %s", strerror(errno));
    }

    close(sock2);
}

#endif

dns_packet_t *DNS_network_send_query_udp(const char *address, char *name, int type) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = inet_addr(address);

    int sock = socket(PF_INET, SOCK_DGRAM, 0);

    // Sets the timeout interval of the socket since we don't expect it to wait forever if the
    // server doesn't response due to some error
    struct timeval timeout = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));

    if (sock < 0) {
        DNS_log_error("[ dns_network] Failed to create UDP socket to send query: %s" ,strerror(errno));
        return NULL;
    }

    dns_packet_t packet = DNS_query_create_request(name, type);
    buffer_t buffer = DNS_buffer_create(BUFFER_SIZE);
    packet_print(packet, addr, true);
    DNS_buffer_write_packet(buffer, packet);
    if (sendto(sock, buffer->ptr, buffer->pos, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        DNS_log_error("[ dns_network] Failed to send UDP packet to DNS server: %s", strerror(errno));
        DNS_buffer_free(buffer);
        close(sock);
        return NULL;
    }

    dns_packet_t *packet_rec = (dns_packet_t *) malloc(sizeof(dns_packet_t));
    buffer_t buffer_rec = DNS_buffer_create(BUFFER_SIZE);
    packet_rec->queries = NULL;
    packet_rec->answers = NULL;
    packet_rec->additionals = NULL;
    packet_rec->authorities = NULL;

    socklen_t addr_len = sizeof(addr);

    // Get the time before and after the response
    struct timeval start, end;
    gettimeofday(&start, NULL);
    if (recvfrom(sock, buffer_rec->ptr, buffer_rec->capacity, 0, (struct sockaddr *) &addr, &addr_len) < 0) {
        DNS_log_error("[ dns_network] Failed to receive UDP packet from DNS server: %s", strerror(errno));
        DNS_buffer_free(buffer_rec);
        free(packet_rec);
        close(sock);
        return NULL;
    }
    gettimeofday(&end, NULL);

    DNS_log_trace("[ dns_network] Server respond in %f ms.", (float) (end.tv_usec - start.tv_usec) / 1000);

    close(sock);

    if (!DNS_buffer_read_packet(buffer_rec, packet_rec)) {
        DNS_log_error("[ dns_network] Failed to decode UDP packet as DNS packet.");
        DNS_buffer_free(buffer_rec);
        free(packet_rec);
        return NULL;
    }

    packet_print(*packet_rec, addr, false);

    return packet_rec;
}

dns_packet_t *DNS_network_send_query_tcp(const char *address, char *name, int type) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = inet_addr(address);

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        DNS_log_error("[ dns_network] Failed to create TCP socket to send query: %s", strerror(errno));
        return NULL;
    }

    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        DNS_log_error("[ dns_network] Failed to connect to the DNS server: %s", strerror(errno));
        return NULL;
    }

    char send_buf[BUFFER_SIZE] = {0};
    dns_packet_t packet = DNS_query_create_request(name, type);
    packet_print(packet, addr, true);
    buffer_t buffer = DNS_buffer_from_ptr(send_buf + 2, BUFFER_SIZE - 2);
    DNS_buffer_write_packet(buffer, packet);
    uint16 len = (uint16) buffer->pos;
    *((uint16 *) send_buf) = htons(len);
    if (send(sock, send_buf, len + 2, 0) < 0) {
        DNS_log_error("[ dns_network] Failed to send TCP packet to DNS server: %s", strerror(errno));
        close(sock);
        return NULL;
    }

    dns_packet_t *packet_rec = (dns_packet_t *) malloc(sizeof(dns_packet_t));
    char buf_rec[BUFFER_SIZE] = {0};
    buffer_t buffer_rec = DNS_buffer_from_ptr(buf_rec + 2, BUFFER_SIZE - 2);
    packet_rec->queries = NULL;
    packet_rec->answers = NULL;
    packet_rec->additionals = NULL;
    packet_rec->authorities = NULL;

    struct timeval start, end;
    gettimeofday(&start, NULL);
    if (recv(sock, buf_rec, sizeof(buf_rec), 0) < 0) {
        DNS_log_error("[ dns_network] Failed to receive TCP packet from DNS server: %s", strerror(errno));
        free(packet_rec);
        return NULL;
    }
    gettimeofday(&end, NULL);

    DNS_log_trace("[ dns_network] Server respond in %f ms.", (float) (end.tv_usec - start.tv_usec) / 1000);

    close(sock);

    if (!DNS_buffer_read_packet(buffer_rec, packet_rec)) {
        DNS_log_error("[ dns_network] Failed to decode TCP packet as DNS packet.");
        DNS_buffer_free(buffer_rec);
        free(packet_rec);
        return NULL;
    }

    packet_print(*packet_rec, addr, false);
    return packet_rec;
}
