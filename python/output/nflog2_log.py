import logging
import ctypes, socket

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_logh as nflog
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl

import ulogd
from scapy.layers.inet import IP


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')


def configure(iklist, oklist):
    oklist.type = ulogd.ULOGD_DTYPE_SINK
    iklist.type = ulogd.ULOGD_DTYPE_RAW
    iklist.add(ulogd.Keyinfo(name="oob.family",
                             type=ulogd.ULOGD_RET_UINT8))
    iklist.add(ulogd.Keyinfo(name="oob.seq.local",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="oob.seq.global",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="raw.pkt",
                             type=ulogd.ULOGD_RET_RAW))
    iklist.add(ulogd.Keyinfo(name="nflog.attrs",
                             type=ulogd.ULOGD_RET_RAW))
    return ulogd.ULOGD_IRET_OK


def start(ikset):
    log.info("start")
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    family = ikset["oob.family"].value
    seq_local = ikset["oob.seq.local"].value
    seq_global = ikset["oob.seq.global"].value
    raw_pkt = ikset["raw.pkt"].value
    pattrs = (ctypes.POINTER(mnl.Attr) * (nflog.NFULA_MAX + 1)).from_address(ikset["nflog.attrs"].value)

    ip = IP(bytes(pattrs[nflog.NFULA_PAYLOAD].contents.get_payload_v()))
    log.info(ip.summary())
    log.info("\tseq - local: %r, global: %r", seq_local, seq_global)
    return ulogd.ULOGD_IRET_OK


def stop():
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
