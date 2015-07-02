import logging
import ctypes, socket

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfq as nfq
import cpylmnfct as nfct

import ulogd
from scapy.layers.inet import IP


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')
nl = mnl.Socket(netlink.NETLINK_NETFILTER)


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
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_ACCEPT)

    nl.send_nlmsg(nlh)


def configure(iklist, oklist):
    oklist.type = ulogd.ULOGD_DTYPE_SINK
    iklist.type = ulogd.ULOGD_DTYPE_RAW
    iklist.add(ulogd.Keyinfo(name="oob.family",
                             type=ulogd.ULOGD_RET_UINT8))
    iklist.add(ulogd.Keyinfo(name="nfq.res_id",
                             type=ulogd.ULOGD_RET_UINT16))
    iklist.add(ulogd.Keyinfo(name="nfq.attrs",
                             type=ulogd.ULOGD_RET_RAW))
    return ulogd.ULOGD_IRET_OK


def start(ikset):
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    res_id = ikset["nfq.res_id"].value
    family = ikset["oob.family"].value
    pattrs = (ctypes.POINTER(mnl.Attr) * (nfqnl.NFQA_MAX + 1))\
        .from_address(ikset["nfq.attrs"].value)

    if pattrs[nfqnl.NFQA_PAYLOAD]:
        ip = IP(bytes(pattrs[nfqnl.NFQA_PAYLOAD].contents.get_payload_v()))
        log.info(ip.summary())

    if pattrs[nfqnl.NFQA_IFINDEX_INDEV]:
        ifin = pattrs[nfqnl.NFQA_IFINDEX_INDEV].contents.get_u32()
        log.info("indev: %d", socket.ntohl(ifin));
    if pattrs[nfqnl.NFQA_IFINDEX_OUTDEV]:
        ifout = pattrs[nfqnl.NFQA_IFINDEX_OUTDEV].contents.get_u32()
        log.info("outdev: %d", socket.ntohl(ifout));

    if pattrs[nfqnl.NFQA_CT]:
        ct = nfct.Conntrack()
        ct.payload_parse(pattrs[nfqnl.NFQA_CT].contents.get_payload_v(), family)
        s = ct.snprintf(4096, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
        log.info("conntrack: %s", s)

    qid = socket.ntohl(pattrs[nfqnl.NFQA_PACKET_HDR].contents.get_payload_as(nfqnl.NfqnlMsgPacketHdr).packet_id)
    nfq_send_accept(res_id, qid)
    return ulogd.ULOGD_IRET_OK


def stop():
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
