could
=====
one of a Child Of ULogD.


feature
-------
### introduce ulogd_source_pluginstance
  スタックの先頭を既存の ulogd_pluginstance ではなく、別構造体 ulogd_source_pluginstance として
  管理。この source pluginstance が、同じ source pluginstance を先頭とする (複数の) stack を持つ。

  introdice ulogd_source_pluginstance instead of ulogd_pluginstance at head of stack.
  ulogd_source_pluginstance hold all stacks which head is this instance.


### verbose data
  同じ source pluginstance を持つ keysets の集まりとして構造体 ulogd_keysets_bundle を導入。
  例えば

  introduce struct ulogd_keysets_bundle for which head is the same source pluginstance.
  for example:

    stack=spi1:src1,pi1:pl1,pi2:pl2,pi3:pl3
    stack=spi1:src1,pi1:pl1,pi4:pl4,pi5:pl5

  とのスタック設定の場合、source pluginstance の spi1 は ulogd_keysets_bundle として
  spi1, pi1, pi2, pi3, pi4, pi5 全ての keysets を含む keysets bundle を作成、保有する。

  in this case, source pluginstance spi1 creates keysets which contains keyset of
  spi1, pi1, pi2, pi3, pi4, pi5. and the source pluginstance holds the keyset.


### multi thread
  今のところ一部のみ。きっかけの source_pluginstance は pthread_create() で作られたスレッド
  ではなく、メインスレッドから呼び出す。source_pluginstance に続くスタックを pthread_create()
  で作られたスレッド上で実行する。

  source pluginstance is not run in thread created by pthread_create(), but in main thread.
  stack which is subsequent of source pluginstance will run in thread created by pthread_create().

### sharing instance
  一つの ID に対してインスタンスを一つだけ作成して共有。
  結果? stack のリストをグローバルに持つのではなく、source_pluginstance が stack を持つ。

  create only one instance per ID and share it.
  so that stack list is not kept in global list but source pluginstance.

    stack=spi1:src1,pi1:pl1,pi2:pl2,pi3:pl3
    stack=spi1:src1,pi1:pl1,pi4:pl4,pi5:pl5
    stack=spi2:src1,pi1:pl1,pi4:pl4,pi5:pl5

  spi1, spi2, pi1, pi2, pi3, pi4, pi5 を一つだけ作成。spi1 は [pi1 pi2 pi3] と [pi1 pi4 pi5]
  二つのスタックを持ち、spi2 は [pi1, pi4, pi5] のスタックを持つ。

  create spi1, spi2, pi1, pi2, pi3, pi4, pi5 only one instance.
  spi1 holds two stack - [pi1 pi2 pi3] and [pi1 pi4 pi5]. spi2 holds [pi1, pi4, pi5]


TODO
----

英語だめだわ...

* investigate and supress compile warnings
* revert db
* would be better to make source pluginstance multi thread?
* use epoll instead of select?


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

    +------------------------------
 ---+ keysets_bundle: .list ---------------------- .list -- (for pool)
    |                 .spi
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

![to propagate](https://github.com/chamaken/could/blob/master/doc/image/propagate.png "propagate")

1. prepare in main.  
   option parsing, instanciate plugin and source_plugin. configure and start those,  
   create keysets_bundle pool for each source pluginstance traversing stack which the  
   source pluginstance has, create interp_threads.  
   source pluginstance may register fd which they will read.  

2. main thread get into ulogd_main_loop().  
   now it is just select() with no timeout.

3. callback.  
   call registered callback if related fd is readable.

4. create output - ulogd_keyset.  
   read data and put it ulogd_keyset which is acquired by ulogd_get_output_keyset()

5. propagate ulogd_keyset.  
   in ulogd_propagate_results() get interp_thread and pass ulogd_keysets_bundle and

6. thread routine.  
   notified ulogd_keysets_bundle prepared by condv. get source pluginstance and  
   traverse each stack which the source pluginstance hold.  
   after execute stack, put ulogd_keysets_bundle back to pool (global list) and  
   put self back to pool too.
