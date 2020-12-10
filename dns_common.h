//
// dns_common.h -- Essential definitions and functions of all other modules
// Created on 5/21/20.
//

#ifndef PROJECT_DNS_DNS_COMMON_H
#define PROJECT_DNS_DNS_COMMON_H

#include "dns_io.h"

// IP addresses for different DNS servers
#define LOCAL_DNS_IP "127.0.0.2"
#define DNS_1_IP "127.0.0.3"
#define DNS_2_IP "127.0.0.4"
#define DNS_3_IP "127.0.0.5"
#define DNS_4_IP "127.0.0.6"
#define ROOT_DNS_IP "127.0.0.7"

// DNS port, can be changed but WireShark will
// not decode the traffic as DNS packets if changed
#define DNS_PORT 53

/**
 * Return code from the server
 */
enum {
    R_NO_ERROR = 0,
    R_FORMAT_ERR,
    R_SERVER_FAILURE,
    R_NOT_EXIST,
    R_QUERY_TYPE_UNSUPPORTED,
    R_DENIED_FOR_POLICY
};

/**
 * The option code, currently we only support Standard Query,
 * We don't check this field in the code, so every query are handled
 * as Standard Query
 */
enum {
    OP_STANDARD_QUERY = 0,
    OP_INVERSE_QUERY,
    OP_SERVER_STATUS
};

/**
 * Supported types of Resource Records
 */
enum {
    TYPE_A = 1,
    TYPE_NS = 2,
    TYPE_CNAME = 5,
    TYPE_PTR = 12,
    TYPE_MX = 15
};

/**
 * Supported classes of Resource Records
 */
enum {
    CLASS_IN = 1
};

/**
 * Print a error message to the terminal.
 * The message will begin with "[ERROR]" and will be colored red
 * (if the ASCII color code is not disabled with NOCOLOR)
 * @param format  The format of the message
 * @param ... The arguments to be formatted to the message
 */
void DNS_log_error(const char *format, ...);

/**
 * Print a warning message to the terminal.
 * The message will begin with "[WARNING]" and will be colored yellow
 * (if the ASCII color code is not disabled with NOCOLOR)
 * @param format  The format of the message
 * @param ... The arguments to be formatted to the message
 */
void DNS_log_warning(const char *format, ...);

/**
 * Print a normal message to the terminal.
 * The message will begin with "[INFO]" and will not be colored
 * @param format  The format of the message
 * @param ... The arguments to be formatted to the message
 */
void DNS_log_info(const char *format, ...);

/**
 * Print a trace message to the terminal.
 * The message will begin with "[TRACE]" and will be colored blue
 * (if the ASCII color code is not disabled with NOCOLOR).
 * This message can be disabled with macro NOTRACE
 * @param format  The format of the message
 * @param ... The arguments to be formatted to the message
 */
void DNS_log_trace(const char *format, ...);

/**
 * Convert a DNS RR type from a string to a 16-bit integer
 * @param str The text representation of the type
 * @return The convert type
 */
uint16 DNS_type_from_str(char *str);

/**
 * Convert a DNS RR type from a 16-bit integer to its text representation
 * @param str The type in 16-bit integer
 * @return The text representation of the type
 */
char *DNS_type_to_str(uint16 type);

/**
 * Convert a DNS RR class from a 16-bit integer to its text representation
 * @param str The class in 16-bit integer
 * @return The text representation of the class
 */
char *DNS_class_to_str(uint16 class);

/**
 * Convert the DNS response code to message
 * @param code The response code from server
 * @return The corresponding message
 */
char *DNS_rcode_to_str(uint8 code);

/**
 * Converts the DNS option code to string
 * @param code The Option code
 * @return The string represent of the code
 */
char *DNS_opcode_to_str(uint8 code);

#endif //PROJECT_DNS_DNS_COMMON_H
