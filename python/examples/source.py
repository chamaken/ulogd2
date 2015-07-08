import logging
import ulogd

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')

timer = None
counter = 0


def timer_callback(t, spi):
    global counter, timer
    
    okset = spi.get_output_keyset()
    okset["sample.counter"].value = counter
    counter += 1
    timer.add(1)
    okset.propagate_results()
    return ulogd.ULOGD_IRET_OK


def configure(okeys):
    okeys.type = ulogd.ULOGD_DTYPE_NULL
    okeys.add(ulogd.Keyinfo(name="sample.counter",
                            type=ulogd.ULOGD_RET_UINT32))
    return ulogd.ULOGD_IRET_OK


def start(spi):
    global counter, timer
    
    timer = ulogd.Timer(timer_callback, spi)
    timer.add(1)
    counter = 0
    return ulogd.ULOGD_IRET_OK


def interp(ikset, okset):
    return ulogd.ULOGD_IRET_OK


def stop():
    timer.delete()
    return ulogd.ULOGD_IRET_OK


def signal(signo):
    log.error("signal: %d" % signo)
