# requires:
# scapy-python3	https://github.com/phaethon/scapy
# cpylm*	https://github.com/chamaken/

import logging
import ctypes, socket, os

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfq as nfq

import ulogd
from scapy.layers.inet import IP


log = None	# logging.getLogger
nl = None	# mnl.Socket


def nfq_hdr_put(buf, nltype, queue_num):
    nlh = mnl.Nlmsg(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nltype
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    return nlh


def nfq_send_accept(queue_num, qid):
    global nl

    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nlh.nlmsg_flags |= netlink.NLM_F_ACK
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_ACCEPT)

    nl.send_nlmsg(nlh)
    nrecv = nl.recv_into(buf)
    return mnl.cb_run(buf[:nrecv], 0, 0, None, None)


def configure(iklist, oklist):
    oklist.type = ulogd.ULOGD_DTYPE_SINK
    iklist.type = ulogd.ULOGD_DTYPE_RAW
    iklist.add(ulogd.Keyinfo(name="nfq.res_id",
                             type=ulogd.ULOGD_RET_UINT16))
    iklist.add(ulogd.Keyinfo(name="nfq.attrs",
                             type=ulogd.ULOGD_RET_RAW))
    return ulogd.ULOGD_IRET_OK


def start(ikset):
    global log, nl
    log = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO,
                        filename='%s_%d.log' % (__name__, os.getpid()),
                        filemode='a',
                        format='%(asctime)s %(levelname)s %(module)s %(message)s')
    nl = mnl.Socket(netlink.NETLINK_NETFILTER)
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    res_id = ikset[0].value
    attrs = mnl.ptrs2attrs(ikset[1].value, nfqnl.NFQA_MAX + 1)
    ph = attrs[nfqnl.NFQA_PACKET_HDR].get_payload_as(nfqnl.NfqnlMsgPacketHdr)
    packet_id = socket.ntohl(ph.packet_id)
    log.info("res_id: %d, qid: %d", res_id, packet_id)
    nfq_send_accept(res_id, packet_id)
    return ulogd.ULOGD_IRET_OK


def stop():
    global nl
    nl.close()
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
