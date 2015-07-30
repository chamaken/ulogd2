#ifndef _ULOGD_RING_H_
#define _ULOGD_RING_H_

#include <linux/netlink.h>
#include <libmnl/libmnl.h>

struct mnl_ring {
	unsigned int		head;
	void			*ring;
	unsigned int		frame_size;
	unsigned int		frame_max;
	unsigned int		block_size;
};

#define MNL_FRAME_PAYLOAD(frame) ((void *)(frame) + NL_MMAP_HDRLEN)

struct mnl_ring *
mnl_socket_rx_mmap(struct mnl_socket *nls, struct nl_mmap_req *req, int flags);
struct mnl_ring *
mnl_socket_tx_mmap(struct mnl_socket *nls, struct nl_mmap_req *req, int flags);
int mnl_socket_unmap(struct mnl_ring *nlr);
void mnl_ring_advance(struct mnl_ring *nlr);
struct nl_mmap_hdr *mnl_ring_get_frame(const struct mnl_ring *nlr);
struct nl_mmap_hdr *mnl_ring_lookup_frame(struct mnl_ring *nlr,
					  enum nl_mmap_status status);

extern char *_frame_status_strlist[];

#endif
