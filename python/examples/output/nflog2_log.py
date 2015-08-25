# requires:
# scapy-python3	https://github.com/phaethon/scapy
# cpylm*	https://github.com/chamaken/

import logging
import ctypes, socket

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_logh as nflog
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfct as nfct

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
    iklist.add(ulogd.Keyinfo(name="oob.prefix",
                             type=ulogd.ULOGD_RET_STRING))
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
    seq_local = ikset[1].value
    seq_global = ikset[2].value
    prefix = ikset[3].value
    raw_pkt = ikset["raw.pkt"].value
    pattrs = (ctypes.POINTER(mnl.Attr) * (nflog.NFULA_MAX + 1)).from_address(ikset["nflog.attrs"].value)

    ip = IP(bytes(pattrs[nflog.NFULA_PAYLOAD].contents.get_payload_v()))
    log.info(ip.summary())
    log.info("\tseq - local: %r, global: %r, prefix: %r", seq_local, seq_global, prefix)

    if pattrs[nflog.NFULA_CT]:
        ct = nfct.Conntrack()
        ct.payload_parse(pattrs[nflog.NFULA_CT].contents.get_payload_v(), family)
        s = ct.snprintf(4096, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
        log.info("conntrack: %s", s)

    return ulogd.ULOGD_IRET_OK


def stop():
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
