#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

int main(int argc, char const *argv[]) {
        /* code */
        int num_paquetes,sockfd,tamano;
        struct sockaddr_in serv_addr;
        struct ifreq ethreq;
        char nombre_red[50];
        char buffer[2000]= {'\0'};;
        int x;
        x=sizeof(struct sockaddr_in);
        sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sockfd < 0) {
                perror("ERROR al abrir socket");
                exit(1);
        }
        else{
                printf("Socket Abierto\n");
        }
        printf("Cuantos paquetes vas a querer analizar?\n");
        scanf("%d",&num_paquetes );
        printf("Cual es el nombre de tu red?\n");
        scanf("%s",nombre_red );
        strcpy(ethreq.ifr_name,nombre_red);
        if(ioctl(sockfd,SIOCGIFFLAGS,&ethreq)<0) {
                perror("Error en oictl uno");
        }
        ethreq.ifr_flags |= IFF_PROMISC;
        if(ioctl(sockfd, SIOCSIFFLAGS,&ethreq)<0) {
                perror("Error en oictl dos");

        }
        struct ether_header *eh = (struct ether_header *) buffer;
        struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ether_header));
        while(1) {
                tamano=  recvfrom(sockfd,buffer,2000,0,(struct sockaddr*)&serv_addr,&x);
                if( tamano<0) {
                        perror("ERROR");
                }
                /* code */
                else{

                      printf("Tamano: %d-Tipo: %.4x  \n", tamano,eh->ether_type);

                }
        }
        close(sockfd);



        return 0;
}
