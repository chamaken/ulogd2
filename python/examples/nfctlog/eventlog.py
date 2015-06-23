import logging, socket
import ulogd

try:
    import ipaddress
except Exception as e:
    import ipaddr
    ipaddress = ipaddr

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')


def configure(iklist, oklist):
    oklist.type = ulogd.ULOGD_DTYPE_SINK
    iklist.type = ulogd.ULOGD_DTYPE_PACKET | ulogd.ULOGD_DTYPE_FLOW
    iklist.add(ulogd.Keyinfo(name="oob.family",
                             type=ulogd.ULOGD_RET_UINT8))
    iklist.add(ulogd.Keyinfo(name="ct.event",
                             type=ulogd.ULOGD_RET_UINT8))
    iklist.add(ulogd.Keyinfo(name="orig.ip.saddr",
                             type=ulogd.ULOGD_RET_IPADDR))
    iklist.add(ulogd.Keyinfo(name="orig.ip.daddr",
                             type=ulogd.ULOGD_RET_IPADDR))
    iklist.add(ulogd.Keyinfo(name="orig.ip.protocol",
                             type=ulogd.ULOGD_RET_UINT8))
    iklist.add(ulogd.Keyinfo(name="orig.raw.pktlen",
                             type=ulogd.ULOGD_RET_UINT64))
    iklist.add(ulogd.Keyinfo(name="orig.raw.pktcount",
                             type=ulogd.ULOGD_RET_UINT64))
    iklist.add(ulogd.Keyinfo(name="reply.raw.pktlen",
                             type=ulogd.ULOGD_RET_UINT64))
    iklist.add(ulogd.Keyinfo(name="reply.raw.pktcount",
                             type=ulogd.ULOGD_RET_UINT64))
    return ulogd.ULOGD_IRET_OK


def start(ikset):
    return ulogd.ULOGD_IRET_OK


events = {0b01: "NEW", 0b10: "UPDATE", 0b100: "DESTROY"}

def interp(ikset, okset):
    family = ikset["oob.family"].value
    if family == socket.AF_INET:
        src = ipaddress.IPv4Address(socket.ntohl(ikset["orig.ip.saddr"].value))
        dst = ipaddress.IPv4Address(socket.ntohl(ikset["orig.ip.daddr"].value))
    elif family == socket.AF_INET6:
        src = ipaddress.IPv6Address(ikset["orig.ip.saddr"].value)
        dst = ipaddress.IPv6Address(ikset["orig.ip.daddr"].value)
    else:
        raise NotImplemented("unknown family: %d" % family)

    ev = ikset["ct.event"].value
    event = "|".join([events[e] for e in filter(lambda x: x & ev != 0, events.keys())])
    proto = ikset["orig.ip.protocol"].value
    orig_len = ikset["orig.raw.pktlen"].value
    orig_count = ikset["orig.raw.pktcount"].value
    reply_len = ikset["reply.raw.pktlen"].value
    reply_count = ikset["reply.raw.pktcount"].value

    log.info("%s - %s => %s [%d]  (=> %d:%d)  (<= %d:%d)" \
                 % (event, src, dst, proto, orig_count, orig_len, reply_count, reply_len))
    return ulogd.ULOGD_IRET_OK


def stop():
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)



