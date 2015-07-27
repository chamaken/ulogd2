# requires:
# scapy-python3	https://github.com/phaethon/scapy
# cpylm*	https://github.com/chamaken/

import logging
import ctypes, socket, struct

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfq as nfq

import ulogd
from scapy.layers.inet import IP, ICMP
from scapy import utils

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')
nl = None # mnl.Socket


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


def nfq_send_repeat(queue_num, qid, mark, payload):
    global nl

    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nlh.nlmsg_flags |= netlink.NLM_F_ACK
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_REPEAT)

    nlh.put_u32(nfqnl.NFQA_MARK, socket.htonl(mark));
    nlh.put(nfqnl.NFQA_PAYLOAD, payload)
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
    global nl
    nl = mnl.Socket(netlink.NETLINK_NETFILTER)    
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    res_id = ikset[0].value
    pattrs = (ctypes.POINTER(mnl.Attr) * (nfqnl.NFQA_MAX + 1)).from_address(ikset[1].value)
    qid = socket.ntohl(pattrs[nfqnl.NFQA_PACKET_HDR].contents.get_payload_as(nfqnl.NfqnlMsgPacketHdr).packet_id)
    log.info("res_id: %d, qid: %d", res_id, qid)

    if pattrs[nfqnl.NFQA_PAYLOAD]:
        nfq_payload = pattrs[nfqnl.NFQA_PAYLOAD].contents
        ip = IP(bytes(nfq_payload.get_payload_v()))

        ip[ICMP].chksum = 0
        icmpb = bytes(ip[ICMP])
        if ip[ICMP].seq % 2 == 0:
            icmpb = bytes(ip[ICMP]).replace(b'#', b'$')
        ip[ICMP] = ip[ICMP].__class__(icmpb)
        ip[ICMP].chksum = utils.checksum(icmpb)

        nfq_send_repeat(res_id, qid, 10, (ctypes.c_ubyte * len(ip)).from_buffer(bytearray(bytes(ip))))
    else:
        nfq_send_accept(res_id, qid)

    return ulogd.ULOGD_IRET_OK


def stop():
    global nl
    nl.close()
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
