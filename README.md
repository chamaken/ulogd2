could?
======
one of a Child Of ULogD. I can't think good name...


feature
-------

compared with the original ulogd:

* unstable
* partial multi-thread
* python plugin
* (working) IPFIX and NetFlow v9 plugin
* mmaped NFCT, NFLOG and NFQUEUE source plugin  
  It cause a kernel panic.  
  see: https://www.mail-archive.com/netdev@vger.kernel.org/msg71352.html


implementation note
-------------------

### introduce ulogd_source_pluginstance
  introduce struct ulogd_source_pluginstance at the head of stack.  
  It holds all stacks which head is this instance.

### verbose data
  introduce struct ulogd_keysets_bundle for which head is the same  
  source pluginstance.

### multi-thread
  source pluginstance is not run in a thread created by  
  pthread_create(), but in main thread. stacks which is subsequent  
  of source pluginstance will run in thread created by  
  pthread_create().

### share instances
  create only one instance per ID from plugin and share it.
  

TODO
----

* naming a good one.
* would it be better to make source pluginstance to multi-thread?  
  multi-threaded source plugin can be implemented, see MTNFQ.
* nft output
* source plugin stacking
* delete or fix unavailable plugins (use static variable as key ptr)


struct memo
-----------

<pre>
source_pluginstance
  .keysets_bundles
   |     .stacks
   |       |
   |       | stack
   |       +-- .list                stack_element     stack_element
   |       |   .elements ------------ .list ------------ .list
   |       |                          .pluginstance
   |       |                          .oksbi ----+
   |       |                          .iksbi -+  |
   |       | stack                            |  |
   |       +-- .list                          |  |
   |       |   .elements ------               |  |
   |       |                                  |  |
   |                                          |  |
   |                                          |  |
   | keysets_bundle                           |  |
   +-- .list                                  |  |
   |      .keysets                            |  |
   |        0: output                         |  |
   |           .keys -------+                 |  |
   |                        |                 |  |
   |        1: input  <-----+-----------------+  |
   |        2: output <-----+--------------------+
   |        3: input        |
   |        4: output       |
   |        ...             |
   |        0: keys <-------+
   |        1: keys
   |
   | keysets_bundle
   +-- .list
   |      .keysets
   |



stack=src,pi1,pi2,...

    +------------------------------                +----
 ---+ keysets_bundle: .list -----------------------+ keysets_bundle: .list -- (for pool)
    |                 .spi                         |
    +-----------------.keysets ----
 0: | src.output: .num_keys, .type, .keys
    +------------------------------
 1: | pi1.input:  .num_keys, .type, .keys -----/
    +------------------------------           /
 2: | pi1.output: .num_keys, .type           /
    +------------------------------         /
    .                                      /
    .                                     /
    +------------------------------      /
    | src.output .keys[0]               v
    +-----------------------------------+
    |            .keys[1]
    +------------------------------
    | pi1.input  .keys[0]
    +------------------------------
    |            .keys[1]
    +------------------------------
    | pi1.output .keys[0]
    +------------------------------
    |            .keys[1], .type: ULOGD_RET_RAW, 
    |                      .len > 0, .value: ----/
    +------------------------------             /
    .                                          /
    .                                         /
    .                                       v
    +---------------------------------------+
    |
    |
    +------------------------------
</pre>

![to propagate](https://github.com/chamaken/ulogd2/blob/v3.x/doc/image/propagate.png "propagate")

1. prepare in main.  
   call configure and start callbacks.  
   source pluginstance may register fd which they will read.

2. main thread get into ulogd_main_loop().  
   wait fds by epoll.

3. ufd or timer callback.
   call registered ufd callback if related fd is readable.

4. create output - ulogd_keyset.  
   source plugin read data from fd and put it to ulogd_keyset which  
   is acquired by ulogd_get_output_keyset()

5. propagate ulogd_keyset.  
   ulogd_propagate_results() gets interp_thread and pass  
   ulogd_keysets_bundle to it (by condv)

6. thread routine.  
   get source pluginstance from ulogd_keyset_bundle and traverse  
   each stack which the source pluginstance hold. After executing  
   stack, put ulogd_keysets_bundle back to pool (global list) and  
   put self back to pool too.
