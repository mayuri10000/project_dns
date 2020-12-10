//
// dns_database.c -- Implementation of database related functions used in the DNS system
//                   The underlying database is sqlite3.
// Created on 5/16/20.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "sqlite3.h"  // sqlite3's source code and header file should be included in the project
#include "dns_common.h"
#include "dns_io.h"

#define DATABASE_NAME "dns_database.db" // the file name of the database, can be changed

sqlite3 *database;

/**
 * Write default testing data to the database.
 * This will add some Resource Records to different DNS servers
 * @return True if the operation is successful
 */
bool DNS_database_write_default_data() {
    char sql_insert[] =
            // Records of root DNS server
            "INSERT INTO root VALUES (1, 'cn',               60, 1, 2, 'ns1.local');"
            "INSERT INTO root VALUES (2, 'us',               60, 1, 2, 'ns1.local');"
            "INSERT INTO root VALUES (3, 'baidu.com',        60, 1, 2, 'ns2.local');"
            "INSERT INTO root VALUES (4, 'code.org',         60, 1, 2, 'ns2.local');"
            "INSERT INTO root VALUES (5, 'ns1.local',        60, 1, 1, '127.0.0.3');"
            "INSERT INTO root VALUES (6, 'ns2.local',        60, 1, 1, '127.0.0.4');"
            "INSERT INTO root VALUES (7, 'in-addr.arpa',     60, 1, 2, 'ns4.local');" // NS for the PTR records
            "INSERT INTO root VALUES (8, 'ns4.local',        60, 1, 1, '127.0.0.6');"

            // Records of DNS server 1
            "INSERT INTO s1   VALUES (1, 'edu.cn',           60, 1, 2, 'ns3.local');"
            "INSERT INTO s1   VALUES (2, 'co.us',            60, 1, 2, 'ns4.local');"
            "INSERT INTO s1   VALUES (3, 'ns3.local',        60, 1, 1, '127.0.0.5');"
            "INSERT INTO s1   VALUES (4, 'ns4.local',        60, 1, 1, '127.0.0.6');"

            // Records of DNS server 2
            "INSERT INTO s2   VALUES (1, 'www.baidu.com',    60, 1, 5, 'www.a.shifen.com');"
            "INSERT INTO s2   VALUES (2, 'www.a.shifen.com', 60, 1, 1, '14.215.177.38');"
            "INSERT INTO s2   VALUES (3, 'www.a.shifen.com', 60, 1, 1, '14.215.177.39');"
            "INSERT INTO s2   VALUES (4, 'tieba.baidu.com',  60, 1, 5, 'post.n.shifen.com');"
            "INSERT INTO s2   VALUES (5, 'post.n.shifen.com',60, 1, 1, '14.215.177.221');"
            "INSERT INTO s2   VALUES (6, 'code.org',         60, 1, 1, '99.84.57.215');"
            "INSERT INTO s2   VALUES (7, 'studio.code.org',  60, 1, 1, '13.227.51.203');"

            // Records of DNS server 3
            "INSERT INTO s3   VALUES (1, 'bupt.edu.cn',      60, 1,15, '3,mx.bupt.edu.cn');"
            "INSERT INTO s3   VALUES (2, 'mx.bupt.edu.cn',   60, 1, 1, '183.3.235.87');"
            "INSERT INTO s3   VALUES (3, 'www.bupt.edu.cn',  60, 1, 5, 'vn64.bupt.edu.cn');"
            "INSERT INTO s3   VALUES (4, 'vn64.bupt.edu.cn', 60, 1, 1, '211.68.69.240');"

            // Records of DNS server 4, contains PTR records
            "INSERT INTO s4   VALUES (1, 'ci.craig.co.us',        60, 1, 1, '50.28.0.27');"
            "INSERT INTO s4   VALUES (2, 'ci.golden.co.us',       60, 1, 1, '66.241.70.19');"
            "INSERT INTO s4   VALUES (3, '2.0.0.127.in-addr.arpa',60, 1,12, 'local.local');"
            "INSERT INTO s4   VALUES (4, '3.0.0.127.in-addr.arpa',60, 1,12, 's1.local');"
            "INSERT INTO s4   VALUES (5, '4.0.0.127.in-addr.arpa',60, 1,12, 's2.local');"
            "INSERT INTO s4   VALUES (6, '5.0.0.127.in-addr.arpa',60, 1,12, 's3.local');"
            "INSERT INTO s4   VALUES (7, '6.0.0.127.in-addr.arpa',60, 1,12, 's4.local');"
            "INSERT INTO s4   VALUES (8, '7.0.0.127.in-addr.arpa',60, 1,12, 'root.local');";

    char *err = NULL;
    sqlite3_exec(database, sql_insert, NULL, NULL, &err);
    if (err != NULL) {
        DNS_log_error("[dns_database] Cannot write default data, %s.", err);
        return false;
    }

    return true;
}

/**
 * Initialize the database. If the database file does not exist,
 * a new one will be created with default data.
 * Note that this should be called for every database operation and the
 * database should be closed after the operation since this database will
 * be used by multiple processes
 * @return True if the database is successfully initialized
 */
bool DNS_database_init() {
    char *err = NULL;  // Error message

    if (access(DATABASE_NAME, F_OK) == -1) {
        DNS_log_warning("[dns_database] Database not found! creating new one...");
        if (sqlite3_open(DATABASE_NAME, &database) != SQLITE_OK) {
            DNS_log_error("[dns_database] Cannot create database, %s", sqlite3_errmsg(database));
            sqlite3_close(database);
            return false;
        }

        char sql_create[] =
                // Create tables for different name servers, for local DNS server, the timestamp field is used to store
                // the time (in seconds) when the cache were added
                "CREATE TABLE root  (id INTEGER PRIMARY KEY, name TEXT, ttl INTEGER, class INTEGER, type INTEGER, data TEXT);"
                "CREATE TABLE s1    (id INTEGER PRIMARY KEY, name TEXT, ttl INTEGER, class INTEGER, type INTEGER, data TEXT);"
                "CREATE TABLE s2    (id INTEGER PRIMARY KEY, name TEXT, ttl INTEGER, class INTEGER, type INTEGER, data TEXT);"
                "CREATE TABLE s3    (id INTEGER PRIMARY KEY, name TEXT, ttl INTEGER, class INTEGER, type INTEGER, data TEXT);"
                "CREATE TABLE s4    (id INTEGER PRIMARY KEY, name TEXT, ttl INTEGER, class INTEGER, type INTEGER, data TEXT);"
                "CREATE TABLE cache (id INTEGER PRIMARY KEY, name TEXT, ttl INTEGER, class INTEGER, type INTEGER, data TEXT, timestamp INTEGER);";

        sqlite3_exec(database, sql_create, NULL, NULL, &err);
        if (err != NULL) {
            DNS_log_error("[dns_database] Cannot crate tables, %s.", err);
            return false;
        }

        if (!DNS_database_write_default_data()) {
            return false;
        }
    }
    else {
        if (sqlite3_open(DATABASE_NAME, &database) != SQLITE_OK) {
            DNS_log_error("[dns_database] Cannot open existing database, %s", sqlite3_errmsg(database));
            sqlite3_close(database);
            return false;
        }
    }

    return true;
}

dns_rr_t *DNS_database_get_record(const char* table_name, char* name, int type, int class, bool include_cname) {
    char **data;
    int columns = 0;
    int count = 0;
    char *err = NULL;
    char sql[256];

    if(!DNS_database_init()) {
        return NULL;
    }
    sprintf(sql, "SELECT * FROM %s WHERE name = '%s' and (type = %d %s) and class = %d;",
            table_name, name, type, (include_cname ? "or type = 5" : "" ), class);

    if (sqlite3_get_table(database, sql, &data, &count, &columns, &err) != SQLITE_OK) {
        DNS_log_error("[dns_database] SQL execution failed, %s\n\t", err, sql);
        sqlite3_close(database);
        return NULL;
    }

    dns_rr_t *first = NULL;
    if (count > 0) {
        dns_rr_t *prev = NULL;

        int index = columns;
        for (int row = 0; row < count; row++) {
            dns_rr_t *t = DNS_RR_create();
            index++;  // Skip the ID field
            sscanf(data[index++], "%s", t->name);
            sscanf(data[index++], "%d", &t->ttl);
            sscanf(data[index++], "%hd", &t->class);
            sscanf(data[index++], "%hd", &t->type);
            sscanf(data[index++], "%s", t->data);
            if (first == NULL) {
                first = t;
                prev = t;
            }
            else {
                prev->next = t;
                prev = t;
            }
        }
        sqlite3_free_table(data);
    }

    sqlite3_close(database);
    return first;
}

dns_rr_t *DNS_database_get_cache(char* name, int type, int class) {
    char **data;
    int columns = 0;
    int count = 0;
    char *err = NULL;
    char sql[256];
    time_t tim = time(NULL);

    if(!DNS_database_init()) {
        return NULL;
    }
    sprintf(sql, "SELECT * FROM cache WHERE name = '%s' and (type = %d or type = 5) and class = %d and timestamp + ttl > %ld;",
            name, type, class, time(&tim));

    if (sqlite3_get_table(database, sql, &data, &count, &columns, &err) != SQLITE_OK) {
        DNS_log_error("[dns_database] SQL execution failed, %s\n\t%s", err, sql);
        sqlite3_close(database);
        return NULL;
    }

    dns_rr_t *first = NULL;
    if (count > 0) {
        dns_rr_t *prev = NULL;

        int index = columns;
        for (int row = 0; row < count; row++) {
            dns_rr_t *t = DNS_RR_create();
            index++;  // Skip the ID field
            sscanf(data[index++], "%s", t->name);
            sscanf(data[index++], "%d", &t->ttl);
            sscanf(data[index++], "%hd", &t->class);
            sscanf(data[index++], "%hd", &t->type);
            sscanf(data[index++], "%s", t->data);
            index++;  // Skip the timestamp field
            if (first == NULL) {
                first = t;
                prev = t;
            }
            else {
                prev->next = t;
                prev = t;
            }
        }
        sqlite3_free_table(data);
    }

    sqlite3_close(database);
    return first;
}

bool DNS_database_put_cache(dns_rr_t rr) {
    char sql_insert[128];
    time_t tim = time(NULL);
    DNS_database_init();

    sprintf(sql_insert, "INSERT INTO cache VALUES (NULL, '%s', %d, %hd, %hd, '%s', %ld);", rr.name, rr.ttl, rr.class, rr.type, rr.data, time(&tim));

    char *err = NULL;
    sqlite3_exec(database, sql_insert, NULL, NULL, &err);
    if (err != NULL) {
        DNS_log_error("[dns_database] Cannot write cache data, %s.", err);
        return false;
    }
    sqlite3_close(database);

    return true;
}