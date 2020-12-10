//
// dns_query.c -- Implementation of DNS query functions
// Created by liu on 5/27/20.
//

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "dns_query.h"
#include "dns_network.h"

dns_packet_t DNS_query_create_request(char *name, int type) {
    dns_packet_t packet;

    packet.header.qr = 0;
    packet.header.opcode = OP_STANDARD_QUERY;
    packet.header.aa = 0;
    packet.header.tc = 0;
    packet.header.rd = 0;
    packet.header.ra = 0;
    packet.header.z = 0;
    packet.header.rcode = 0;
    packet.header.question_count = 0;
    packet.header.additional_count = 0;
    packet.header.answer_count = 0;
    packet.header.authority_count = 0;
    packet.queries = NULL;
    packet.answers = NULL;
    packet.additionals = NULL;
    packet.authorities = NULL;

    dns_query_t *query = DNS_query_create();
    strcpy(query->name, name);
    query->type = (uint16) type;
    query->class = CLASS_IN;
    DNS_packet_append_query(&packet, query, true);

    return packet;
}


#ifndef CLIENT
// Some server-only code that we don't expect in the client
#include "dns_database.h"

const char *table_name;

dns_packet_t DNS_query_create_fail_response(int rcode) {
    dns_packet_t response;

    response.header.qr = 1;
    response.header.opcode = OP_STANDARD_QUERY;
    response.header.aa = 0;
    response.header.tc = 0;
    response.header.rd = 0;
    response.header.ra = 0;
    response.header.z = 0;
    response.header.rcode = rcode;
    response.header.question_count = 0;
    response.header.answer_count = 0;
    response.header.additional_count = 0;
    response.header.authority_count = 0;
    response.queries = NULL;
    response.answers = NULL;
    response.additionals = NULL;
    response.authorities = NULL;

    return response;
}

void DNS_query_set_table_name(const char *name) {
    table_name = name;
}

/**
 * Add element to a linked list, used in {@code DNS_query_create_response}
 * and {@code DNS_query_create_response_local}
 */
#define add_to_linked_list(linked_list, value) \
    if (linked_list##_first == NULL) {                       \
        linked_list##_first = value;                         \
        linked_list##_last = value;                          \
    }                                                        \
    else {                                                   \
        linked_list##_last->next = value;                    \
        linked_list##_last = linked_list##_last->next;       \
    }

dns_packet_t DNS_query_create_response(dns_packet_t request) {
    dns_packet_t response;

    response.header.id = request.header.id;
    response.header.qr = 1;
    response.header.opcode = OP_STANDARD_QUERY;
    response.header.aa = 0;
    response.header.tc = 0;
    response.header.rd = 0;
    response.header.ra = 0;
    response.header.z = 0;
    response.header.rcode = R_NO_ERROR;
    response.header.question_count = 0;
    response.header.answer_count = 0;
    response.header.additional_count = 0;
    response.header.authority_count = 0;
    response.queries = NULL;
    response.answers = NULL;
    response.additionals = NULL;
    response.authorities = NULL;

    dns_query_t *query;
    bool have_invaild_mode = false;

    for (query = request.queries; query != NULL; query = query->next) {
        ptr_t name_ = query->name;
        uint16 type = query->type;
        uint16 class = query->class;
        dns_rr_t *data;

        // Check if there are invalid query types and classes
        if (!strcmp(DNS_type_to_str(query->type), "[UNKNOWN]")) {
            have_invaild_mode = true;
            continue;
        }

        if (!strcmp(DNS_class_to_str(query->class), "[UNKNOWN]")) {
            have_invaild_mode = true;
            continue;
        }

        // Append queries
        dns_query_t *query2 = DNS_query_copy(query);
        DNS_packet_append_query(&response, query2, true);

        dns_rr_t *cname_pending_first = NULL, *cname_pending_last = NULL;
        dns_rr_t *add_pending_first = NULL, *add_pending_last = NULL;

        data = DNS_database_get_record(table_name, name_, type, class, true);

        // Search for matching records of given name and type
        // This will also include CNAME records
        for (dns_rr_t *t = data; t != NULL; t = t->next) {
            dns_rr_t *t2 = DNS_RR_copy(t);

            if (t->type == TYPE_CNAME && type != TYPE_CNAME) {
                dns_rr_t *tt = DNS_RR_copy(t);
                add_to_linked_list(cname_pending, tt);
            }
            else {
                DNS_packet_append_answer(&response, t2, true);
            }

            // For MX-typed RRs, we should look for their IP addresses later
            if (t->type == TYPE_MX) {
                dns_rr_t *tt = DNS_RR_copy(t);
                add_to_linked_list(add_pending, tt);
            }
        }

        // For the found CNAME results, get the corresponding records.
        // If any other CNAME is found, then it will also be parsed
        for (dns_rr_t *t = cname_pending_first; t != NULL; t = t->next) {
            dns_rr_t *data2 = DNS_database_get_record(table_name, t->data, type, class, true);

            if (data2 != NULL) {
                dns_rr_t *t4 = DNS_RR_copy(t);
                DNS_packet_append_answer(&response, t4, true);
            }
            else {
                // CNAME RRs will not be appended to the packet if the query is not CNAME type and the
                // RR does not have a related RR of the queried type
                DNS_log_warning("[  dns_query ] Found CNAME record %s but not found its corresponding record.",
                        t->data);
            }

            for (dns_rr_t *tt = data2; tt != NULL; tt = tt->next) {
                dns_rr_t *t2 = DNS_RR_copy(tt);

                if (tt->type == TYPE_CNAME && type != TYPE_CNAME) {
                    dns_rr_t *t3 = DNS_RR_copy(tt);
                    add_to_linked_list(cname_pending, t3);
                }
                else {
                    DNS_packet_append_answer(&response, t2, true);
                }

                if (tt->type == TYPE_MX) {
                    dns_rr_t *t3 = DNS_RR_copy(tt);
                    add_to_linked_list(add_pending, t3);
                }
            }
        }

        // Break down the name into pieces and find authoritative name servers.
        for (ptr_t c = name_; *c != '\0'; c++) {
            if (*(c - 1) == '.' || c == name_) {
                data = DNS_database_get_record(table_name, c, TYPE_NS, class, false);

                for (dns_rr_t *t = data; t != NULL; t = t->next) {
                    dns_rr_t *t2 = DNS_RR_copy(t);
                    DNS_packet_append_authority(&response, t2, true);

                    dns_rr_t *t3 = DNS_RR_copy(t);
                    add_to_linked_list(add_pending, t3);
                }
            }
        }

        // Search for the IP address of the domain names in records of type MX and NS
        // Note that we assume that these domain names don't have canonical names
        for (dns_rr_t *t = add_pending_first; t != NULL; t = t->next) {
            char name[128];
            if (t->type == TYPE_MX) {
                int nc;
                if (sscanf(t->data, "%d,%s", &nc, name) != 2) {
                    DNS_log_warning("[  dns_query ] Expected preference and name in MX record, but only get name");
                    strcpy(name, t->data);
                }
            }
            else {
                strcpy(name, t->data);
            }
            dns_rr_t *data2 = DNS_database_get_record(table_name, name, TYPE_A, class, false);

            if (data2 == NULL) {
                DNS_log_warning("[  dns_query ] The IP address of name %s could not be found.", name);
            }

            for (dns_rr_t *tt = data2; tt != NULL; tt = tt->next) {
                dns_rr_t *t2 = DNS_RR_copy(tt);
                DNS_packet_append_additional(&response, t2, true);
            }
        }
    }

    // If there is no RRs in the packet, change the response code
    if (!response.header.answer_count && !response.header.authority_count && !response.header.additional_count )
        response.header.rcode = R_NOT_EXIST;

    if (have_invaild_mode)
        response.header.rcode = R_QUERY_TYPE_UNSUPPORTED;

    return response;
}

dns_packet_t DNS_query_create_response_local(dns_packet_t request) {
    dns_packet_t response;

    response.header.id = request.header.id;
    response.header.qr = 1;
    response.header.opcode = OP_STANDARD_QUERY;
    response.header.aa = 0;
    response.header.tc = 0;
    response.header.rd = 0;
    response.header.ra = 0;
    response.header.z = 0;
    response.header.rcode = R_NO_ERROR;
    response.header.question_count = 0;
    response.header.answer_count = 0;
    response.header.additional_count = 0;
    response.header.authority_count = 0;
    response.queries = NULL;
    response.answers = NULL;
    response.additionals = NULL;
    response.authorities = NULL;

    dns_query_t *query;
    bool have_invaild_mode = false;

    for (query = request.queries; query != NULL; query = query->next) {
        ptr_t name = name = query->name;
        uint16 type = query->type;
        uint16 class = query->class;

        if (!strcmp(DNS_type_to_str(query->type), "[UNKNOWN]")) {
            have_invaild_mode = true;
            continue;
        }

        if (!strcmp(DNS_class_to_str(query->class), "[UNKNOWN]")) {
            have_invaild_mode = true;
            continue;
        }

        dns_query_t *query2 = DNS_query_copy(query);
        DNS_packet_append_query(&response, query2, true);

        // Search local cache
        dns_rr_t *cache = DNS_database_get_cache(name, type, class);

        // Handle the cache
        if (cache != NULL) {
            DNS_log_trace("[  dns_query ] Record found in local cache: %s %s", DNS_type_to_str(type), name);

            dns_rr_t *cname_pending_first = NULL, *cname_pending_last = NULL;
            dns_rr_t *add_pending_first = NULL, *add_pending_last = NULL;

            for (dns_rr_t *t = cache; t != NULL; t = t->next) {

                // If the cache entry have the type of CNAME
                // we should look for their actual address later
                // (only whe the query type is not CNAME)
                if (t->type == TYPE_CNAME && type != TYPE_CNAME) {
                    dns_rr_t *r = DNS_RR_copy(t);
                    add_to_linked_list(cname_pending, r);
                }
                else {
                    dns_rr_t *tt = DNS_RR_copy(t);
                    DNS_packet_append_answer(&response, tt, true);
                }

                // If the cache entry have the type MX
                // We should look for their IP addresses later
                if (t->type == TYPE_MX) {
                    dns_rr_t *r = DNS_RR_copy(t);
                    add_to_linked_list(add_pending, r);
                }
            }

            // Looks up the address of the CNAMEs, recursive CNAMEs will be added to the list
            // during this procedure
            for (dns_rr_t *t = cname_pending_first; t != NULL; t = t->next) {
                dns_rr_t *data2 = DNS_database_get_cache(t->data, type, class);

                if (data2 == NULL) {
                    DNS_log_warning(
                            "[  dns_query ] The cache contains CNAME record %s but the corresponding record cannot be found",
                            t->data);
                } else {
                    DNS_packet_append_answer(&response, DNS_RR_copy(t), true);
                    for (dns_rr_t *t2 = data2; t2 != NULL; t2 = t2->next) {
                        // Found recursive CNAME
                        if (t2->type == TYPE_CNAME && type != TYPE_CNAME) {
                            dns_rr_t *r = DNS_RR_copy(t2);
                            add_to_linked_list(cname_pending, r);
                        }
                        else {
                            DNS_packet_append_answer(&response, DNS_RR_copy(t2), true);
                        }

                        if (t2->type == TYPE_MX) {
                            dns_rr_t *r = DNS_RR_copy(t2);
                            add_to_linked_list(add_pending, r);
                        }
                    }
                }
            }

            // Look for the IP addresses for the MX records
            for (dns_rr_t *t = add_pending_first; t != NULL; t = t->next) {
                char name[128];
                if (t->type == TYPE_MX) {
                    int nc;
                    bool found = false;
                    if (sscanf(t->data, "%d,%s", &nc, name) != 2) {
                        DNS_log_warning("[  dns_query ] Expected preference and name in MX record, but only get name");
                        strcpy(name, t->data);
                    }
                }
                else {
                    strcpy(name, t->data);
                }
                dns_rr_t *data2 = DNS_database_get_cache(name, TYPE_A, class);

                if (data2 == NULL) {
                    DNS_log_warning(
                            "[  dns_query ] The cache contains MX record %s but the IP address of the MX server cannot be found",
                            t->data);
                } else {
                    for (dns_rr_t *t2 = data2; t2 != NULL; t2 = t2->next) {
                        if (t2->type == TYPE_A) {
                            DNS_packet_append_additional(&response, DNS_RR_copy(t2), true);
                        }
                    }
                }
            }
        }
        else {
            // Not found in the cache, should start iterative query
            DNS_log_warning("[  dns_query ] Record not found in local cache, start iterative query...");

            // The name servers to be queried
            dns_rr_t *ns_pending_first = NULL, *ns_pending_last = NULL;

            // Adds the root name server to the list of name servers
            ns_pending_first = DNS_RR_create();
            strcpy(ns_pending_first->name, "root.local");
            strcpy(ns_pending_first->data, ROOT_DNS_IP);
            ns_pending_first->class = CLASS_IN;
            ns_pending_first->type = type;
            ns_pending_first->next = NULL;
            ns_pending_last = ns_pending_first;

            // Make requests to each of the name servers. Additional name servers found
            // will be added to the name servers list
            for (dns_rr_t *ns = ns_pending_first; ns != NULL; ns = ns->next) {
                DNS_log_trace("[  dns_query ] Sending query request to %s (%s)", ns->name ,ns->data);
                dns_packet_t *ns_res = DNS_network_send_query_udp(ns->data, name, type);

                if (ns_res != NULL) {
                    for (dns_rr_t *t = ns_res->answers; t != NULL; t = t->next) {
                        dns_rr_t *tt = DNS_RR_copy(t);
                        DNS_packet_append_answer(&response, tt, true);
                        DNS_database_put_cache(*t);

                        if (t->type == TYPE_MX) {
                            char name[128];
                            int nc;
                            bool found = false;
                            if (sscanf(t->data, "%d,%s", &nc, name) != 2) {
                                DNS_log_warning("[  dns_query ] Expected preference and name in MX record, but only get name");
                                strcpy(name, t->data);
                            }

                            for (dns_rr_t *t2 = ns_res->additionals; t2 != NULL; t2 = t2->next) {
                                if (!strcmp(t2->name, name)) {
                                    dns_rr_t *ttt = DNS_RR_copy(t2);
                                    DNS_packet_append_additional(&response, ttt, true);
                                    DNS_database_put_cache(*t2);
                                    found = true;
                                }
                            }

                            if (!found)
                                DNS_log_warning("[   dns_query ] The IP address of the MX record %s cannot be found.", name);
                        }
                    }

                    // Next level of name servers
                    for (dns_rr_t *t = ns_res->authorities; t != NULL; t = t->next) {
                        bool found = false;
                        for (dns_rr_t *t2 = ns_res->additionals; t2 != NULL; t2 = t2->next) {
                            if (!strcmp(t->data, t2->name) && t2->type == TYPE_A) {
                                found = true;
                                ns_pending_last->next = DNS_RR_copy(t2);
                                ns_pending_last = ns_pending_last->next;
                            }
                        }
                        if (!found)
                            DNS_log_warning("[  dns_query ] In the response of server %s, the address of %s is not given",
                                    ns->data, t->data);
                    }
                }
            }
        }
    }

    if (!response.header.answer_count && !response.header.authority_count && !response.header.additional_count )
        response.header.rcode = R_NOT_EXIST;

    if (have_invaild_mode)
        response.header.rcode = R_QUERY_TYPE_UNSUPPORTED;

    return response;
}

#endif