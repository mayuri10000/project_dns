# Disable the CMake version limit
# cmake_minimum_required(VERSION 3.16)
project(Project_DNS C)

set(CMAKE_C_STANDARD 99)
# Make sure the compiler use C99 standard
set(CMAKE_C_FLAGS "-std=c99")

# Source files for the server executable
add_executable(dns_server
        dns_server.c
        dns_database.c  dns_database.h
        sqlite3.c       sqlite3.h
        dns_common.c    dns_common.h
        dns_io.c        dns_io.h
        dns_network.c   dns_network.h
        dns_query.c     dns_query.h)

# Source files for the client executable
add_executable(dns_client
        dns_client.c
        dns_common.c    dns_common.h
        dns_io.c        dns_io.h
        dns_network.c   dns_network.h
        dns_query.c     dns_query.h )

# Add the "CLIENT" definition to the client code to exclude server-only codes
set_target_properties(dns_client PROPERTIES COMPILE_DEFINITIONS "CLIENT")

# required for the sqlite library
target_link_libraries(dns_server dl pthread)
