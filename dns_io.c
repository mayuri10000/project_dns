//
// dns_io.c -- Provides implementation of the buffer read/write functions
// Created on 5/26/20.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns_common.h"
#include "dns_io.h"

/**
 * Ensures the operation successes, otherwise print the error and exit the current function
 */
#define ENSURE_SUCCESS(func) \
    if (!func) {             \
        DNS_log_error("[   dns_io   ] %s (Line %d) failed, Buffer boundary reached", __FUNCTION__, __LINE__ ); \
        return false; \
    }

/**
 * Check whether the buffer have enough remaining space of a operation
 * @param buffer The buffer
 * @param size The required size of current operation
 * @return True if the buffer have enough remaining space
 */
bool check_capacity(buffer_t buffer, int size) {
    if (buffer->pos + size > buffer->capacity) {
        return false;
    }
    return true;
}

buffer_t DNS_buffer_create(int capacity) {
    buffer_t buf = (buffer_t) malloc(sizeof(struct dns_buffer));
    if (buf == NULL) {
        DNS_log_error("[   dns_io   ] Cannot create buffer struct, out of memory.");
        return NULL;
    }

    buf->ptr = (ptr_t) malloc(capacity);
    if (buf->ptr == NULL) {
        DNS_log_error("[   dns_io   ] Failed to create buffer with length %d, out of memory.", capacity);
        return NULL;
    }

    buf->capacity = capacity;
    buf->pos = 0;
    buf->known_names = NULL;
    memset(buf->ptr, 0, buf->capacity);

    return buf;
}

buffer_t DNS_buffer_from_ptr(ptr_t ptr, int capacity) {
    buffer_t buf = (buffer_t) malloc(sizeof(struct dns_buffer));
    if (buf == NULL) {
        DNS_log_error("[   dns_io   ] Cannot create buffer struct, out of memory.");
        return NULL;
    }

    buf->ptr = ptr;
    buf->capacity = capacity;
    buf->pos = 0;
    buf->known_names = NULL;
    return buf;
}

void DNS_buffer_free(buffer_t buffer) {
    free(buffer->ptr);
    free(buffer);
}

dns_rr_t *DNS_RR_create() {
    dns_rr_t *rr = (dns_rr_t *) malloc(sizeof(dns_rr_t));
    if (rr == NULL) {
        DNS_log_error("[   dns_io   ] Cannot create RR struct, out of memory.");
        return NULL;
    }

    rr->data = (ptr_t) malloc(128);
    rr->name = (ptr_t) malloc(128);
    rr->next = NULL;
    return rr;
}

dns_query_t *DNS_query_copy(dns_query_t *other) {
    if (other == NULL) {
        return NULL;
    }

    dns_query_t *ret = DNS_query_create();
    strcpy(ret->name, other->name);
    ret->type = other->type;
    ret->class = other->class;
    ret->next = NULL;
    return ret;
}

dns_rr_t *DNS_RR_copy(dns_rr_t *other) {
    if (other == NULL) {
        return NULL;
    }

    dns_rr_t *ret = DNS_RR_create();
    strcpy(ret->name, other->name);
    strcpy(ret->data, other->data);
    ret->type = other->type;
    ret->class = other->class;
    ret->ttl = other->ttl;
    ret->next = NULL;
    return ret;
}

dns_query_t *DNS_query_create() {
    dns_query_t *query = (dns_query_t *) malloc(sizeof(dns_query_t));
    if (query == NULL) {
        DNS_log_error("[   dns_io   ] Cannot create query struct, out of memory");
    }

    query->name = (ptr_t) malloc(128);
    query->next = NULL;
    return query;
}

void DNS_packet_append_query(dns_packet_t *packet, dns_query_t *query, bool increase_count) {
    if (packet->queries == NULL) {
        packet->queries = query;
    }
    else {
        dns_query_t *t;
        for (t = packet->queries; t->next != NULL; t = t->next);
        t->next = query;
    }

    if (increase_count)
        packet->header.question_count++;
}

void DNS_packet_append_answer(dns_packet_t *packet, dns_rr_t *rr, bool increase_count) {
    if (packet->answers == NULL) {
        packet->answers = rr;
    }
    else {
        dns_rr_t *t;
        for (t = packet->answers; t->next != NULL; t = t->next);
        t->next = rr;
    }

    if (increase_count)
        packet->header.answer_count++;
}

void DNS_packet_append_authority(dns_packet_t *packet, dns_rr_t *rr, bool increase_count) {
    if (packet->authorities == NULL) {
        packet->authorities = rr;
    }
    else {
        dns_rr_t *t;
        for (t = packet->authorities; t->next != NULL; t = t->next);
        t->next = rr;
    }

    if (increase_count)
        packet->header.authority_count++;
}

void DNS_packet_append_additional(dns_packet_t *packet, dns_rr_t *rr, bool increase_count) {
    if (packet->additionals == NULL) {
        packet->additionals = rr;
    }
    else {
        dns_rr_t *t;
        for (t = packet->additionals; t->next != NULL; t = t->next);
        t->next = rr;
    }

    if (increase_count)
        packet->header.additional_count++;
}


bool DNS_buffer_read_u8(buffer_t buffer, uint8 *v) {
    // Check whether the position is still in the valid range
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(uint8)));

    *v = buffer->ptr[buffer->pos++];
    return true;
}

bool DNS_buffer_write_u8(buffer_t buffer, uint8 v) {
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(uint8)));

    buffer->ptr[buffer->pos++] = v;
    return true;
}

bool DNS_buffer_read_u16(buffer_t buffer, uint16 *v) {
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(uint16)));

    *v = (buffer->ptr[buffer->pos++] << 8) |
         (buffer->ptr[buffer->pos++] << 0);
    return true;
}

bool DNS_buffer_write_u16(buffer_t buffer, uint16 v) {
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(uint16)));

    buffer->ptr[buffer->pos++] = (uint8) (v >> 8);
    buffer->ptr[buffer->pos++] = (uint8) (v >> 0);
    return true;
}

bool DNS_buffer_read_u32(buffer_t buffer, uint32 *v) {
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(uint32)));

    *v = (buffer->ptr[buffer->pos++] << 24) |
         (buffer->ptr[buffer->pos++] << 16) |
         (buffer->ptr[buffer->pos++] << 8) |
         (buffer->ptr[buffer->pos++] << 0);
    return true;
}

bool DNS_buffer_write_u32(buffer_t buffer, uint32 v) {
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(uint32)));

    buffer->ptr[buffer->pos++] = (uint8) (v >> 24);
    buffer->ptr[buffer->pos++] = (uint8) (v >> 16);
    buffer->ptr[buffer->pos++] = (uint8) (v >> 8);
    buffer->ptr[buffer->pos++] = (uint8) (v >> 0);
    return true;
}

bool DNS_buffer_read_DNS_header(buffer_t buffer, dns_header_t *v) {
    ENSURE_SUCCESS(check_capacity(buffer, sizeof(dns_header_t)));
    memcpy(v, &buffer->ptr[buffer->pos], sizeof(dns_header_t));
    buffer->pos += sizeof(dns_header_t);

    v->id = ntohs(v->id);
    v->question_count = ntohs(v->question_count);
    v->answer_count = ntohs(v->answer_count);
    v->authority_count = ntohs(v->authority_count);
    v->additional_count = ntohs(v->additional_count);
    return true;
}

bool DNS_buffer_write_DNS_header(buffer_t buffer, dns_header_t v) {
    v.id = htons(v.id);
    v.question_count = htons(v.question_count);
    v.answer_count = htons(v.answer_count);
    v.authority_count = htons(v.authority_count);
    v.additional_count = htons(v.additional_count);

    ENSURE_SUCCESS(check_capacity(buffer, sizeof(dns_header_t)));
    memcpy(&buffer->ptr[buffer->pos], &v, sizeof(dns_header_t));
    buffer->pos += sizeof(dns_header_t);
    return true;
}

/**
 * Find a name from the known names in the buffer with its position
 * @param buffer
 * @param position
 * @return The name
 */
ptr_t known_names_find_name(buffer_t buffer, uint16 position) {
    for (known_name_t *k = buffer->known_names; k != NULL; k = k->next) {
        if (k->pos == position) {
            return k->name;
        }
    }

    return NULL;
}

/**
 * Find the position of the name in the known names of the buffer
 * @param buffer
 * @param name
 * @return The position, 0xFFFF if not found
 */
uint16 known_names_find_pos(buffer_t buffer, ptr_t name) {
    for (known_name_t *k = buffer->known_names; k != NULL; k = k->next) {
        if (!strcmp(name, k->name)) {
            return k->pos;
        }
    }

    return 0xFFFF;
}

/**
 * Append a new name to the known names of the buffer
 * @param buffer
 * @param name
 * @param position
 */
void known_names_append(buffer_t buffer, ptr_t name, uint16 position) {
    known_name_t *k = buffer->known_names;

    known_name_t *kk = (known_name_t *) malloc(sizeof(known_name_t));
    kk->name = (ptr_t) malloc(64);
    ptr_t named = kk->name;
    uint8 length_tag2;
    while (*name != '\0') {
        length_tag2 = *name++;
        if ((length_tag2 >> 6) == 0b11) {
            uint16 ptr = ((length_tag2 & 0x3F) << 8) | *name++;
            ptr_t found_name = known_names_find_name(buffer, ptr);
            if (found_name != NULL) {
                strcpy(named, found_name);
                named += strlen(found_name);
            }
            break;
        }

        *named++ = length_tag2;
        for (int i = 0; i < length_tag2; i++) {
            *named++ = *name++;
        }
    }
    *named = '\0';
    kk->pos = position;
    kk->next = NULL;

    if (k == NULL) {
        buffer->known_names = kk;
    }
    else {
        for (; k->next != NULL; k = k->next);
        k->next = kk;
    }
}


bool DNS_buffer_read_DNS_name(buffer_t buffer, ptr_t name) {
    uint8 length_tag;
    do {
        ENSURE_SUCCESS(DNS_buffer_read_u8(buffer, &length_tag));

        if ((length_tag >> 6) != 0b11 && length_tag != 0) {
            ENSURE_SUCCESS(check_capacity(buffer, length_tag));
            // Append the current name to the known names
            // This will add the string from current length tag to the final tag (\0)
            known_names_append(buffer, &buffer->ptr[buffer->pos - 1], buffer->pos - 1);

            uint8 c;
            for (int i = 0; i < length_tag; i++) {
                ENSURE_SUCCESS(DNS_buffer_read_u8(buffer, &c));
                *name++ = c;
            }
            *name++ = '.'; // Append dots to the string
        } else if ((length_tag >> 6) == 0b11) {  // This is a pointer to another position of the packet
            uint16 ptr;
            uint8 ptr8;
            ENSURE_SUCCESS(DNS_buffer_read_u8(buffer, &ptr8));
            ptr = ((length_tag & 0x3F) << 4) | ptr8;
            ptr_t name1 = known_names_find_name(buffer, ptr);  // Find the position in the known names
            if (name1 == NULL) {
                DNS_log_warning("[   dns_io   ] One of the pointers in the packet does not points to a name");
            }
            else {
                uint8 length_tag2;
                while (*name1 != '\0') {
                    length_tag2 = *name1++;
                    for (int i = 0; i < length_tag2; i++) {
                        *name++ = *name1++;
                    }
                    *name++ = '.';
                }
            }
            break;
        }
    } while (length_tag > 0);

    *(name - 1) = '\0';  // Remove last dot (.) and write termination of string

    return true;
}

bool DNS_buffer_write_DNS_name(buffer_t buffer, ptr_t name) {
    buffer_t converted_name = DNS_buffer_create(strlen(name) + 2);
    ptr_t tok = strtok(name, ".");
    uint8 length_tag;
    // Convert the domain name to machine format
    while (tok) {
        length_tag = (uint8) strlen(tok);
        DNS_buffer_write_u8(converted_name, length_tag);
        for (int i = 0; i < length_tag; i++) {
            DNS_buffer_write_u8(converted_name, tok[i]);
        }
        tok = strtok(NULL, ".");
    }

    if (!check_capacity(buffer, converted_name->capacity)) {
        return false;
    }

    length_tag = 0;
    converted_name->pos = 0;
    // Process the segments of name respectively
    do {
        // Try to find existing names on the buffer
        uint16 find = known_names_find_pos(buffer, &converted_name->ptr[converted_name->pos]);
        if (find != 0xFFFF) {
            // If found, write its position instead of its actual value
            DNS_buffer_write_u16(buffer, find | 0xC000);
            break;
        }

        // Read the length tags
        ENSURE_SUCCESS(DNS_buffer_read_u8(converted_name, &length_tag));

        // Append the current name to the known names
        if (length_tag != 0)
            known_names_append(buffer, &converted_name->ptr[converted_name->pos - 1], buffer->pos);

        // Write the length tag
        ENSURE_SUCCESS(DNS_buffer_write_u8(buffer, length_tag));
        for (int i = 0; i < length_tag; i++) {
            // Write the content of the name
            ENSURE_SUCCESS(DNS_buffer_write_u8(buffer, converted_name->ptr[converted_name->pos++]));
        }
    } while (length_tag > 0);

    return true;
}

bool DNS_buffer_read_RR(buffer_t buffer, dns_rr_t *v) {
    ENSURE_SUCCESS(DNS_buffer_read_DNS_name(buffer, v->name));
    ENSURE_SUCCESS(DNS_buffer_read_u16(buffer, &v->type));
    ENSURE_SUCCESS(DNS_buffer_read_u16(buffer, &v->class));
    ENSURE_SUCCESS(DNS_buffer_read_u32(buffer, &v->ttl));
    ENSURE_SUCCESS(DNS_buffer_read_u16(buffer, &v->length));

    ENSURE_SUCCESS(check_capacity(buffer, v->length));

    int pos = buffer->pos;
    if (v->type == TYPE_A) {
        if (v->length != 4) {
            DNS_log_warning("[   dns_io   ] Inconsistent RR data length of type A, 4 is expected but got %d", v->length);
            memcpy(v->data, buffer->ptr, v->length);
            buffer->pos += v->length;
        } else {
            uint32 iip;
            struct in_addr addr;
            ENSURE_SUCCESS(DNS_buffer_read_u32(buffer, &iip));
            addr.s_addr = ntohl(iip);
            strcpy(v->data, inet_ntoa(addr));
        }
    } else if (v->type == TYPE_MX) {
        uint16 preference;
        unsigned char data[128];

        ENSURE_SUCCESS(DNS_buffer_read_u16(buffer, &preference));
        ENSURE_SUCCESS(DNS_buffer_read_DNS_name(buffer, data));
        sprintf(v->data, "%hd,%s", preference, data);
    } else {
        ENSURE_SUCCESS(DNS_buffer_read_DNS_name(buffer, v->data));
    }

    if (buffer->pos - pos != v->length) {
        DNS_log_warning("[   dns_io   ] Read %d bytes of RR data, but %d bytes is expected.", (buffer->pos - pos),
                        v->length);
        buffer->pos = pos + v->length;
    }

    return true;
}

bool DNS_buffer_write_RR(buffer_t buffer, dns_rr_t v) {
    ENSURE_SUCCESS(DNS_buffer_write_DNS_name(buffer, v.name));

    ENSURE_SUCCESS( DNS_buffer_write_u16(buffer, v.type));
    ENSURE_SUCCESS(DNS_buffer_write_u16(buffer, v.class));
    ENSURE_SUCCESS(DNS_buffer_write_u32(buffer, v.ttl));
    int pos = buffer->pos;
    buffer->pos += 2;       // Skip the length field for now, we will add it later

    if (v.type == TYPE_A) {
        uint32 iip = htonl(inet_addr(v.data));
        ENSURE_SUCCESS(DNS_buffer_write_u32(buffer, iip));
        if (iip == -1) {
            DNS_log_warning("[   dns_io   ] Expected IP address in RR of type A, but got '%s'.", v.data);
        }
    } else if (v.type == TYPE_MX) {
        uint16 pref;
        char name[128];

        if (sscanf(v.data, "%hd,%s", &pref, name) != 2) {
            DNS_log_warning(
                    "[   dns_io   ] Expected preference and name in RR of type MX, but got '%s', the preference will be set to 0",
                    v.data);
            // memset(name, 0, 128);
            ENSURE_SUCCESS(DNS_buffer_write_u16(buffer, 0));
            ENSURE_SUCCESS(DNS_buffer_write_DNS_name(buffer, v.data));
        } else {
            ENSURE_SUCCESS(DNS_buffer_write_u16(buffer, pref));
            ENSURE_SUCCESS(DNS_buffer_write_DNS_name(buffer, name));
        }
    } else {
        ENSURE_SUCCESS(DNS_buffer_write_DNS_name(buffer, v.data));
    }

    int pos2 = buffer->pos;
    uint16 len = pos2 - pos - 2;

    buffer->pos = pos;
    DNS_buffer_write_u16(buffer, len);
    buffer->pos = pos2;

    return true;
}

bool DNS_buffer_read_query(buffer_t buffer, dns_query_t *v) {
    ENSURE_SUCCESS(DNS_buffer_read_DNS_name(buffer, v->name));
    ENSURE_SUCCESS(DNS_buffer_read_u16(buffer, &v->type));
    ENSURE_SUCCESS(DNS_buffer_read_u16(buffer, &v->class));
    return true;
}

bool DNS_buffer_write_query(buffer_t buffer, dns_query_t v) {
    ENSURE_SUCCESS(DNS_buffer_write_DNS_name(buffer, v.name));
    ENSURE_SUCCESS(DNS_buffer_write_u16(buffer, v.type));
    ENSURE_SUCCESS(DNS_buffer_write_u16(buffer, v.class));
    return true;
}

bool DNS_buffer_read_packet(buffer_t buffer, dns_packet_t *v) {
    ENSURE_SUCCESS(DNS_buffer_read_DNS_header(buffer, &v->header));

    int i;
    for (i = 0; i < v->header.question_count; i++) {
        dns_query_t *query = DNS_query_create();
        ENSURE_SUCCESS(DNS_buffer_read_query(buffer, query));
        DNS_packet_append_query(v, query, false);
    }

    for (i = 0; i < v->header.answer_count; i++) {
        dns_rr_t *answer = DNS_RR_create();
        ENSURE_SUCCESS(DNS_buffer_read_RR(buffer, answer));
        DNS_packet_append_answer(v, answer, false);
    }

    for (i = 0; i < v->header.authority_count; i++) {
        dns_rr_t *authority = DNS_RR_create();
        ENSURE_SUCCESS(DNS_buffer_read_RR(buffer, authority));
        DNS_packet_append_authority(v, authority, false);
    }

    for (i = 0; i < v->header.additional_count; i++) {
        dns_rr_t *additional = DNS_RR_create();
        ENSURE_SUCCESS(DNS_buffer_read_RR(buffer, additional));
        DNS_packet_append_additional(v, additional, false);
    }

    return true;
}

bool DNS_buffer_write_packet(buffer_t buffer, dns_packet_t v) {
    ENSURE_SUCCESS(DNS_buffer_write_DNS_header(buffer, v.header));

    int i;
    for (dns_query_t *k = v.queries; k != NULL; k = k->next) {
        ENSURE_SUCCESS(DNS_buffer_write_query(buffer, *k));
    }

    for (dns_rr_t *k = v.answers; k != NULL; k = k->next) {
        ENSURE_SUCCESS(DNS_buffer_write_RR(buffer, *k));
    }

    for (dns_rr_t *k = v.authorities; k != NULL; k = k->next) {
        ENSURE_SUCCESS(DNS_buffer_write_RR(buffer, *k));
    }

    for (dns_rr_t *k = v.additionals; k != NULL; k = k->next) {
        ENSURE_SUCCESS(DNS_buffer_write_RR(buffer, *k));
    }

    return true;
}