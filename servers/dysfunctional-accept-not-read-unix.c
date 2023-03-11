// Copyright © 2022 Kris Nóva <nova@nivenly.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <arpa/inet.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Note: This needs to match the upstream{} config in nginx.conf
#define SOCK "/var/run/nginx-proxy-analysis.sock"
#define BUFFER_SIZE 1024

int main() {
  char buffer[BUFFER_SIZE];
  char resp[] = "HTTP/1.0 200 OK\r\n"
                "Server: upstream-basic-server-tcp-c\r\n"
                "Content-type: text/html\r\n\r\n"
                "<html>Nginx Proxy Test Server</html>\r\n";

  // Unlink any preexisting socket.
  unlink(SOCK);

  // Create a new socket.
  int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("webserver (socket)");
    return 1;
  }
  //printf("socket created successfully\n");

  // Create the unix domain socket addr
  struct sockaddr_un host_addr;
  int host_addrlen = sizeof(host_addr);

  host_addr.sun_family = AF_UNIX;
  strncpy(host_addr.sun_path, SOCK, sizeof(host_addr.sun_path) - 1);

//  host_addr.sin_family = AF_INET;
//  host_addr.sin_port = htons(PORT);
//  host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

// Create client address
struct sockaddr_in client_addr;
int client_addrlen = sizeof(client_addr);

  // Bind the socket to the address
  if (bind(sockfd, (struct sockaddr *)&host_addr, host_addrlen) != 0) {
    perror("webserver (bind)");
    return 1;
  }
  //printf("socket successfully bound to address\n");

  // Listen for incoming connections
  if (listen(sockfd, SOMAXCONN) != 0) {
    perror("webserver (listen)");
    return 1;
  }
  //printf("server listening for connections\n");

  for (;;) {
    // Accept incoming connections
    int newsockfd = accept(sockfd, (struct sockaddr *)&host_addr,
                           (socklen_t *)&host_addrlen);
    if (newsockfd < 0) {
      perror("webserver (accept)");
      continue;
    }
    //printf("connection accepted\n");

    // Get client address
    int sockn = getsockname(newsockfd, (struct sockaddr *)&client_addr,
                            (socklen_t *)&client_addrlen);
    if (sockn < 0) {
      perror("webserver (getsockname)");
      continue;
    }

    // No longer read().

  }

  return 0;
}