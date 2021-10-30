#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "iphdr.h"
#include "tcphdr.h"

char* host; 

bool check_http_header(char* payload)
{
	const char* methods[] = {"GET","HEAD","POST","PUT","DELETE","CONNECT","OPTIONS","TRACE","PATCH"};
	char* ptr = strtok(payload,"\r\n");
	if(ptr == NULL) return false;
	bool chk = false;
	for(int i=0;i<sizeof(methods)/sizeof(char*);i++)
	{
		if(strncmp(ptr,methods[i],strlen(methods[i])) == 0)
		{
			chk = true;
			break;
		}	
	}
	if(!chk) return false;

	ptr = strtok(NULL,"\r\n");
	if(ptr == NULL) return false;
	ptr = strstr(ptr,host);
	if(ptr == NULL) return false;
	if(strcmp(ptr,host) != 0) return false;
	return true;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *packet;
	uint16_t protocol;
	PIpHdr iphdr;
	PTcpHdr tcphdr;
	unsigned char *payload;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(nfa, &packet);
	if (ret >= 0)
	{
		iphdr = (PIpHdr)packet;
		if(iphdr->protocol != 0x06) goto ACCEPT;
		int t_len = iphdr->tlen();
		int ip_len = ((iphdr->h_v)&0x0f)<<2;
		tcphdr = (PTcpHdr)(packet+ip_len);
		if(tcphdr->dport() != 80 && tcphdr->sport() != 80) goto ACCEPT; 
		int offset = ip_len + ((tcphdr->offset)<<2);
		if(t_len - offset == 0) goto ACCEPT;
		payload = packet + offset;
		bool chk = check_http_header((char*)payload);
		if(!chk) goto ACCEPT;
	}

	printf("entering callback\n");
	
	DROP:
	puts("packet blocked!");
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

	ACCEPT:
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage()
{
	puts("syntax : sudo netfilter-test <host>\nsample : sudo netfilter-test test.gilgil.net");
}

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		usage();
		return -1;
	}
	else host = argv[1];

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
