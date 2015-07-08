import logging
import ulogd

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')


def configure(ikeys, okeys):
    okeys.type = ulogd.ULOGD_DTYPE_SINK
    ikeys.type = ulogd.ULOGD_DTYPE_NULL
    ikeys.add(ulogd.Keyinfo(name="sample.counter",
                            type=ulogd.ULOGD_RET_UINT32))
    return ulogd.ULOGD_IRET_OK


def start(ikset):
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    log.info("sample.counter: %d", ikset["sample.counter"].value)
    return ulogd.ULOGD_IRET_OK


def stop():
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
