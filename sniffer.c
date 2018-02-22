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
#include <netinet/ip.h>    //Provides declarations for ip header
int cont_ieee=0,cont_eth=0;
int cont_ipv4=0,cont_ipv6=0,cont_flujo=0,cont_arp=0,cont_seg=0;
void EscribirTipoDireccion(FILE *logfile,u_char *dir){

        if (dir[0]==0xFF && dir[1]==0xFF &&dir[2]==0xFF &&dir[3]==0xFF &&dir[4]==0xFF &&dir[5]==0xFF) {
                /* code */
                fprintf(logfile,"\t\t\t\tDIFUSION\n");
        }
        else if (dir[0]%2==0) {
                /* code */
                fprintf(logfile,"\t\t\t\tUNIDIFUSION\n");

        }
        else{
                fprintf(logfile,"\t\t\t\tMULTIDIFUSION\n");

        }

}
void EscribirTrama(FILE *logfile,const u_char *buffer,int tamano){

        struct ether_header *eth = (struct ether_header *) buffer;
        if(ntohs(eth->ether_type)>=0x0600) {
                fprintf(logfile," IEEE 802.3 ");

                cont_ieee++;
                switch(ntohs(eth->ether_type)) {
                case 0x0800:
                        fprintf(logfile, "\t\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5] );
                        fprintf(logfile, " \t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5] );
                        fprintf(logfile, "\t\tIPv4");
                        if(tamano>=60) {
                                fprintf(logfile, "  \t%d",tamano);
                                fprintf(logfile, "  \t\t%d",tamano-14-20);
                        }
                        else{
                                fprintf(logfile, "  \t60");
                                fprintf(logfile, "  \t\t30");

                        }
                        EscribirTipoDireccion(logfile,eth->ether_dhost);
                        cont_ipv4++;
                        break;
                case 0x86dd:
                        fprintf(logfile, "\t\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5] );
                        fprintf(logfile, " \t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5] );
                        fprintf(logfile, "\t\tIPv6");
                        if(tamano>=60) {
                                fprintf(logfile, "  \t\t%d",tamano);
                                fprintf(logfile, "  \t%d",tamano-14);
                        }
                        else{
                                fprintf(logfile, "  \t\t60");
                                fprintf(logfile, "  \t\t50");

                        }
                        EscribirTipoDireccion(logfile,eth->ether_dhost);
                        cont_ipv6++;
                        break;

                case 0x0806:
                        fprintf(logfile, "\t\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5] );
                        fprintf(logfile, " \t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5] );
                        fprintf(logfile, "\t\tARP");
                        if(tamano>=60) {
                                fprintf(logfile, "  \t%d",tamano);
                                fprintf(logfile, "  \t\t%d",tamano-14);
                        }
                        else{
                                fprintf(logfile, "  \t60");
                                fprintf(logfile, "  \t\t50");

                        }            EscribirTipoDireccion(logfile,eth->ether_dhost);
                        cont_arp++;
                        break;

                case 0x8808:
                        fprintf(logfile, "\t\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5] );
                        fprintf(logfile, " \t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5] );
                        fprintf(logfile, "\t\tFLUJO ETHERNET");
                        if(tamano>=60) {
                                fprintf(logfile, "  \t\t%d",tamano);
                                fprintf(logfile, "  \t%d",tamano-14);
                        }
                        else{
                                fprintf(logfile, "  \t\t60");
                                fprintf(logfile, "  \t\t50");

                        }                 EscribirTipoDireccion(logfile,eth->ether_dhost);
                        cont_flujo++;
                        break;

                case 0x88E5:
                        fprintf(logfile, "\t\t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5] );
                        fprintf(logfile, " \t%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5] );
                        fprintf(logfile, " \t\tSeguridad MAC");
                        if(tamano>=60) {
                                fprintf(logfile, "  \t\t%d",tamano);
                                fprintf(logfile, "  \t%d",tamano-14);
                        }
                        else{
                                fprintf(logfile, "  \t\t60");
                                fprintf(logfile, "  \t\t50");

                        }                   EscribirTipoDireccion(logfile,eth->ether_dhost);
                        cont_seg++;
                        break;

                default:
                        printf("NADA\n" );

                }
        }
        else{
                fprintf(logfile,"\n\t\t\t\t\t\t**************Trama no analizable (ETHERNET ||)***************\n\n");
                cont_eth++;
        }

}
int main(int argc, char const *argv[]) {
        /* code */
        FILE *logfile;
        logfile=fopen("log.txt","w");
        if(logfile==NULL)
        {
                printf("No podemos crear archivo");
        }
        fprintf(logfile, "Alberto Angel Ramirez Aguilera\nPractica 2B : Sniffer\n");
        fprintf(logfile,"Tipo de trama\t\tMAC DESTINO\t\tMAC ORIGEN\t\tPROTOCOLO\tTRAMA\tCARGA UTIL\t\t\tDIRECCION\n");
        int num_paquetes,sockfd,tamano;
        struct sockaddr_in serv_addr;
        struct ifreq ethreq;
        char nombre_red[50];
        char buffer[2000];
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
        for(int i=0; i<num_paquetes; i++) {
                tamano=  recvfrom(sockfd,buffer,2000,0,(struct sockaddr*)&serv_addr,&x);
                if( tamano<0) {
                        perror("ERROR");
                }
                else{
                        EscribirTrama(logfile,buffer,tamano);

                }
        }
        printf("Escaneo finalizado\n");
        fprintf(logfile, "TOTAL DE TRAMAS ANALIZADAS : %d\n", cont_ieee+cont_eth);
        fprintf(logfile," Numero de Tramas IEEE 802.3 : %d \n Numero de Tramas Ethernet II : %d \n",cont_ieee,cont_eth);
        fprintf(logfile," IPv4 : %d \n IPv6 : %d \n Resolucion de Direcciones : %d \n Flujo Ethernet : %d \n Seguridad MAC : %d",cont_ipv4,cont_ipv6,cont_arp,cont_flujo,cont_seg);
        close(sockfd);
        fclose(logfile);



        return 0;
}
