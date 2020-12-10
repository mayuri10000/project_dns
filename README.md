# Simple DNS system
* This project is the final project of *Internet Application*. It implements a simple DNS system
with one six name servers (including one root name server and a local name server) and a DNS client program.
* This DNS system can process queries of type A, MX, CNAME and PTR. For MX records, the IP address of the
mail exchanger server will also be added to the response.

## Compilation and execution
This project is organized by CMake. To compile the code, run the following commands in the terminal:
```shell script
mkdir build
cd build
cmake ..
make
```
Then the executables will be generated. Run the server with specific mode with one of the following command:
```shell script
# "sudo" should be used since most linux distribution don't allow 
# non-root to bind on port number lower than 1024
sudo ./dns_server root  # starts the root name server
sudo ./dns_server s1    # starts the 1st name server
sudo ./dns_server s2    # starts the 2nd name server
sudo ./dns_server s3    # starts the 3rd name server
sudo ./dns_server s4    # starts the 4th name server
sudo ./dns_server local # starts the local name server
```
To execute the client, using the following command after starting all the servers:
```shell script
./dns_client bupt.edu.cn MX  # you can change the query name and type
```
All the traffic between the client and the local server and the traffic between local DNS server and other servers
can be decoded correctly with WireShark.

You can also send DNS query with `nslookup` to the servers, remember we should specify the query type otherwise `nslookup`
will send queries with unsupported type:
```shell script
# When querying from a non-local server
nslookup -query=A www.baidu.com 127.0.0.4  
# When querying from the local server, "-vc" is to do the query with TCP protocol  
nslookup -vc -query=MX bupt.edu.cn 127.0.0.2 
```

## Data
This project use SQLite3 database to store all the Resource Records and the local cache. The database will 
be created with default RRs when the program is executed for the first time. You can add RRs to the database with
and SQLite3 management tools. The library code required for SQLite3 databases are already added to the source code 
directory, so the project can be built without any external dependence. 