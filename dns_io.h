//
// dns_io.h -- Contains IO functions of the DNS system, like buffers.
// Created on 5/26/20.
//

#ifndef PROJECT_DNS_DNS_IO_H
#define PROJECT_DNS_DNS_IO_H

#define true  1
#define false 0

// some type definition
typedef unsigned char *ptr_t;
typedef unsigned char bool;
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

/**
 * The DNS Packet header
 */
typedef struct {
    uint16 id;       /// < The Identification number, request should match with response

    uint8 rd:1;
    uint8 tc:1;
    uint8 aa:1;
    uint8 opcode:4;

    uint8 qr:1;     /// < Response or request
    uint8 rcode:4;   // Flag fields in one bit should be in inverted order.
    uint8 z:3;
    uint8 ra:1;
    uint16 question_count;
    uint16 answer_count;
    uint16 authority_count;
    uint16 additional_count;
} dns_header_t;

/**
 * The DNS query
 * Stores as linked list
 */
typedef struct dns_query {
    ptr_t name;
    uint16 type;
    uint16 class;

    struct dns_query *next;
} dns_query_t;

/**
 * The DNS resource record
 * Stores as linked list
 */
typedef struct dns_rr {
    ptr_t name;
    uint16 type;
    uint16 class;
    uint32 ttl;
    uint16 length;
    ptr_t data;

    struct dns_rr *next;
} dns_rr_t;

/**
 * The DNS packet struct.
 * The queries and RRs are stored as linked lists
 */
typedef struct {
    dns_header_t header;
    dns_query_t *queries;
    dns_rr_t *answers;
    dns_rr_t *authorities;
    dns_rr_t *additionals;
} dns_packet_t;

/**
 * This struct records one known name and its position in the buffer
 * This struct is stored in a linked list
 */
typedef struct known_name {
    ptr_t name;
    uint16 pos;
    struct known_name *next;
} known_name_t;

/**
 * This struct contains the pointer, length, capacity and current position of a buffer
 */
struct dns_buffer {
    ptr_t ptr;
    uint32 capacity;
    uint32 pos;

    // The known names in the buffer
    known_name_t *known_names;
};

/**
 * The pointer to the buffer struct
 */
typedef struct dns_buffer *buffer_t;

/**
 * Create a buffer with specified capacity
 * @param capacity The capacity of the buffer
 * @return The pointer to the buffer struct
 */
buffer_t DNS_buffer_create(int capacity);

/**
 * Create a buffer with existing memory pointer.
 * @param ptr The pointer of the buffer begins
 * @param capacity The capacity of the buffer
 * @return The buffer object
 */
buffer_t DNS_buffer_from_ptr(ptr_t ptr, int capacity);

/**
 * Release the memory space taken by the buffer
 * @param buffer The buffer to be released
 */
void DNS_buffer_free(buffer_t buffer);

dns_query_t *DNS_query_create();

dns_rr_t *DNS_RR_create();

dns_query_t *DNS_query_copy(dns_query_t *other);

/**
 * copies an RR pointer. Since the RR is a linked table node
 * so it must be copied (not referenced) if you want to add it to
 * another linked list
 * @param other
 * @return
 */
dns_rr_t *DNS_RR_copy(dns_rr_t *other);

void DNS_packet_append_query(dns_packet_t *packet, dns_query_t *query, bool increase_count);

void DNS_packet_append_answer(dns_packet_t *packet, dns_rr_t *rr, bool increase_count);

void DNS_packet_append_authority(dns_packet_t *packet, dns_rr_t *rr, bool increase_count);

void DNS_packet_append_additional(dns_packet_t *packet, dns_rr_t *rr, bool increase_count);

// The following functions read/write unsigned integers from buffer with BIG ENDIAN
bool DNS_buffer_read_u8(buffer_t buffer, uint8 *v);
bool DNS_buffer_write_u8(buffer_t buffer, uint8 v);
bool DNS_buffer_read_u16(buffer_t buffer, uint16 *v);
bool DNS_buffer_write_u16(buffer_t buffer, uint16 v);
bool DNS_buffer_read_u32(buffer_t buffer, uint32 *v);
bool DNS_buffer_write_u32(buffer_t buffer, uint32 v);

bool DNS_buffer_read_DNS_header(buffer_t buffer, dns_header_t *v);

bool DNS_buffer_write_DNS_header(buffer_t buffer, dns_header_t v);

/**
 * Read DNS name from the buffer and convert it to human readable format.
 * For example, the names in the buffer will like '\003www\005baidu\003com\0'
 * and it should be converted to 'www.baidu.com'
 * @param buffer
 * @param name
 * @return True if the operation is success
 */
bool DNS_buffer_read_DNS_name(buffer_t buffer, ptr_t name);

/**
 * Write DNS name to the buffer. The name will be converted to format like
 * '\003www\005baidu\003com\0'. For existing names in the same packet, pointers to
 * the name will be used
 * @param buffer
 * @param name
 * @return
 */
bool DNS_buffer_write_DNS_name(buffer_t buffer, ptr_t name);

bool DNS_buffer_read_RR(buffer_t buffer, dns_rr_t *v);

bool DNS_buffer_write_RR(buffer_t buffer, dns_rr_t v);

bool DNS_buffer_read_query(buffer_t buffer, dns_query_t *v);

bool DNS_buffer_write_query(buffer_t buffer, dns_query_t v);

bool DNS_buffer_read_packet(buffer_t buffer, dns_packet_t *v);

bool DNS_buffer_write_packet(buffer_t buffer, dns_packet_t v);

#endif //PROJECT_DNS_DNS_IO_H
