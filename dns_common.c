//
// Created on 5/27/20.
//

#define LOG_BUFFER_LEN 1024

#ifdef NOCOLOR              // Set NOCOLOR macro in the CMakeLists file to disable console color.
#define COLOR_RED     ""    // In some platform the colors might not display correctly
#define COLOR_GREEN   ""
#define COLOR_YELLOW  ""
#define COLOR_BLUE    ""
#define COLOR_MAGENTA ""
#define COLOR_CYAN    ""
#define COLOR_RESET   ""

#define COLOR_RED_B     ""
#define COLOR_GREEN_B   ""
#define COLOR_YELLOW_B  ""
#define COLOR_BLUE_B    ""
#define COLOR_MAGENTA_B ""
#define COLOR_CYAN_B    ""
#else
#define COLOR_RED     "\x1b[31m"   // ASCII Color code
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

#define COLOR_RED_B     "\x1b[01;31m"
#define COLOR_GREEN_B   "\x1b[01;32m"
#define COLOR_YELLOW_B  "\x1b[01;33m"
#define COLOR_BLUE_B    "\x1b[01;34m"
#define COLOR_MAGENTA_B "\x1b[01;35m"
#define COLOR_CYAN_B    "\x1b[01;36m"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "dns_io.h"
#include "dns_common.h"

// The Logging macro
#define DNS_LOG(format, color, level) \
    char buf[LOG_BUFFER_LEN];\
    va_list list;\
    va_start(list, format);\
    vsnprintf(buf, LOG_BUFFER_LEN, format, list);\
    va_end(list);\
    printf(color level "%s\n" COLOR_RESET, buf);\


void DNS_log_error(const char *format, ...) {
    DNS_LOG(format, COLOR_RED_B, "[ ERROR ] ");
}

void DNS_log_warning(const char *format, ...) {
    DNS_LOG(format, COLOR_YELLOW_B, "[WARNING] ");
}

void DNS_log_info(const char *format, ...) {
    DNS_LOG(format, COLOR_RESET, "[  INFO ] ");
}

void DNS_log_trace(const char *format, ...) {
#ifndef NOTRACE
    DNS_LOG(format, COLOR_BLUE_B, "[ TRACE ] ");
#endif
}

uint16 DNS_type_from_str(char *str) {
    if (!strcmp(str, "A")) {
        return TYPE_A;
    }
    else if (!strcmp(str, "NS")) {
        return TYPE_NS;
    }
    else if (!strcmp(str, "MX")) {
        return TYPE_MX;
    }
    else if (!strcmp(str, "PTR")) {
        return TYPE_PTR;
    }
    else if (!strcmp(str, "CNAME")) {
        return TYPE_CNAME;
    }
    else {
        DNS_log_error("[ dns_common ] Unknown DNS type '%s'", str);
        return 0;
    }
}

char *DNS_type_to_str(uint16 type) {
    if (type == TYPE_A) {
        return "A";
    }
    else if (type == TYPE_NS) {
        return "NS";
    }
    else if (type == TYPE_MX) {
        return "MX";
    }
    else if (type == TYPE_PTR) {
        return "PTR";
    }
    else if (type == TYPE_CNAME) {
        return "CNAME";
    }
    else {
        DNS_log_error("[ dns_common ] The DNS type %d is currently not supported.", type);
        return "[UNKNOWN]";
    }
}

char *DNS_class_to_str(uint16 class) {
    if (class == CLASS_IN) {
        return "IN";
    }
    else {
        DNS_log_error("[ dns_common ] The DNS class %d is currently not supported.", class);
        return "[UNKNOWN]";
    }
}

char *DNS_rcode_to_str(uint8 code) {
    if (code == R_NO_ERROR) {
        return "No Error";
    }
    else if (code == R_SERVER_FAILURE) {
        return "Server failure";
    }
    else if (code == R_FORMAT_ERR) {
        return "Format error";
    }
    else if (code == R_NOT_EXIST) {
        return "Name does not exists";
    }
    else if (code == R_QUERY_TYPE_UNSUPPORTED) {
        return "Unsupported query type";
    }
    else if (code == R_DENIED_FOR_POLICY) {
        return "Query denied for policy";
    }
    else {
        return "Unknown error";
    }
}

char *DNS_opcode_to_str(uint8 code) {
    if (code == OP_STANDARD_QUERY) {
        return "Standard query";
    }
    else if (code == OP_INVERSE_QUERY) {
        return "Inverse query";
    }
    else if (code == OP_SERVER_STATUS) {
        return "Server status";
    }
    else {
        return "Unknown query";
    }
}