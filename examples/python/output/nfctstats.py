import logging, socket
import ulogd

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')


def configure(iklist, oklist):
    oklist.type = ulogd.ULOGD_DTYPE_SINK
    iklist.type = ulogd.ULOGD_DTYPE_FLOW # XXX: introduce ULOGD_DTYPE_STATS?
    iklist.add(ulogd.Keyinfo(name="nfct.stats.searched",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.found",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.new",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.invalid",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.ignore",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.delete",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.delete_list",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.insert",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.insert_failed",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.drop",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.early_drop",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.error",
                             type=ulogd.ULOGD_RET_UINT32))
    iklist.add(ulogd.Keyinfo(name="nfct.stats.search_restart",
                             type=ulogd.ULOGD_RET_UINT32))
    return ulogd.ULOGD_IRET_OK


def start(ikset):
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    log.info("\n\tsearched: %d, found: %d, new: %d, invalid: %d, ignore: %d"
             "\n\tdelete: %d, delete_list: %d, insert: %d, insert_failed: %d"
             "\n\tdrop: %d, early_drop: %d, error: %d, search_restart: %d",
             ikset[0].value, ikset[1].value, ikset[2].value, ikset[3].value, ikset[4].value,
             ikset[5].value, ikset[6].value, ikset[7].value, ikset[8].value,
             ikset[9].value, ikset[10].value, ikset[11].value, ikset[12].value);
    return ulogd.ULOGD_IRET_OK


def stop():
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
