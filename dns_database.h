//
// dns_database.h -- Provide definitions for local data related operations
// Created by root on 5/28/20.
//

#ifndef PROJECT_DNS_DNS_DATABASE_H
#define PROJECT_DNS_DNS_DATABASE_H

#include "dns_io.h"

dns_rr_t *DNS_database_get_record(const char* table_name, char* name, int type, int class, bool include_cname);
dns_rr_t * DNS_database_get_cache(char* name, int type, int class);
bool DNS_database_put_cache(dns_rr_t rr);

#endif //PROJECT_DNS_DNS_DATABASE_H
