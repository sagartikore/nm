// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#define PORT 8001
#define SPORT 11000
  
int main(int argc, char const *argv[])
{
    struct sockaddr_in address;
    int sock[100], valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};
    int i;
    for(i = 0; i < 100; i++) {
      if ((sock[i] = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      {
        printf("\n Socket creation error \n");
        return -1;
      }
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("169.254.9.3"); //INADDR_ANY;

      
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    int sport = atoi(argv[2]) ;

    for (i = 0; i < 100; i++) {
      sport = sport + 1;
      address.sin_port = htons( sport );
      if (bind(sock[i], (struct sockaddr *)&address,
            sizeof(address))<0)
      {
        printf("failed\n");
        exit(EXIT_FAILURE);
      }
    }

    for (i = 0; i < 100; i++) {
      if (connect(sock[i], (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
      {
        printf("\nCongffgfnection Failed \n");
        return -1;
      }
      send(sock[i] , hello , strlen(hello) , 0 );
      printf("Hello message sent\n");
      valread = read( sock[i] , buffer, 1024);
      printf("%s\n",buffer );
     close(sock[i]);
    }
    return 0;

}
