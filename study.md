### 参考书籍
  - 深入理解nginx
  - 深入剖析nginx
  - 淘宝nginx书籍.
    [参考链接](http://tengine.taobao.org/book/chapter_02.html#id1)
### 待学习
  - nginx的配置手册
    > [配置手册](http://shouce.jb51.net/nginx/left.html)
  - upstream
  - subrequest
    - ngx_http_upstream_init_round_robin
  - SSL是如何支持的.
  - gzip模块.
  - chunk模块.
  - 能否撰写流模式的反病毒引擎？是否有开源的反病毒程序？
  - tnginx
    - sysgurad模块. 据说这个模块在真实server的情况下很有用.
  - nginx跟踪调试
    [获取链接](https://www.cnblogs.com/jimodetiantang/p/9188789.html)
  - nginx如何保证sub request的顺序.
  - nginx header_filter/body_filter设计原理.
  - proxy_pass DNS如何获得?
  - [nginx从入门到精通](https://www.kancloud.cn/kancloud/master-nginx-develop/51833)
  - nginx stream模块.
  - [网易云课堂里](https://study.163.com/course/introduction.htm?courseId=1005083015#/courseDetail?tab=1)
  - nginx文件操作. 
    aio 机制.
  - nginx-copy filter.
  - nginx应用场景.
    https://docs.nginx.com/nginx/admin-guide/
  - nginx内存池的申请.
    - 每个不同的buffer对应不同的内存池？？对应的原则是什么？
  - nginx cache manager 机制
  - nginx named location
    - 内部重定向用，外部client不能通过名称访问.
  - nginx nested location
    

### 主要特性
  - 与apache相比
    > apache一个进程处理一个连接. 每个进程不停的停止，以等待所需资源得到满足.
    > nginx采用事件处理模型，一个进程处理多个http连接.   
      > 时延，并发，性能都得到有效的提升.   
      > 每个事务都不能掉用阻塞函数，否则其他事务将无法得到调用，增加编程的难度.    
  - 全进程工作模式
    - 1 master & 多个worker
    - 为什么module里会有init_thread这个函数指针???
  - 全异步工作方式
    - 通过epoll等异步方式进行操作, 非常高效. 
    - 如果不小心掉用了阻塞操作，将会极大的影响nginx的性能.
### 模块
  - 定义
    - module
      - ctx
      - commands 
      - init_master
      - init_process
      - init_module
    
### 配置
  - 格式
    > 命令行 + 参数(可以多个).  
    > 每一个关键字都是一个命令, 如http/server/location都有对应的命令. 
    > 可以自定义命令。  
  - 匹配顺序
    - 普通表达式匹配优先.
      - 实例
        ```
        location = /a/hello.html {
            echo "hello equal match";
        }
        ```
      - 普通表达式按最长匹配优先.
    - 前缀匹配(明确指定，它优先于正则表达式
      - 实例
        ```
        location ^~ /a/hello.html {
            echo "hello equal match";
        }
        ```
    - 正则表达式.
      - 实例
        ```
        location ~ /hello(.*)$ {
            echo "hello reg1";
        }
        ```
      - 正则表达式之间配置顺序优先
      - 如果匹配两个正则表达式，则第一个正则表达式生效. 
      
    - 前缀匹配.
      - 实例
        ```
        location /a/b/c/ {
            echo "/a/b/c/";
        }
        ```
    - named location.
      - 作为内部重定向用，不在查找范围之内.
      - named/internel location不会继承原request的ctx.
      - 实例
        ```
        location / {
            error_page 404 = @fallback;
        }

        location @fallback {
            proxy_pass http://backend;
        }
        ```
    - 注意, nginx 没有后缀匹配
    - 注意, nginx 支持location嵌套.
    - [参考文档](https://blog.csdn.net/fengmo_q/article/details/6683377)
    - [参考文档](https://www.cnblogs.com/lidabo/p/4169396.html)
    
  - 配置执行顺序
    - create_config
    - command_handler
    - init_config
  - 继承结构
    > 参见《深入理解nginx》第10章.
    
  - 注意问题:
    - flag的值一定要初始化成-1，否则会报错.
    - merge_loc_conf函数一定要写, 否则会出现配置不对的现象.
    - complex_value的str，不一定是以\0结尾. 
    
### ngixn 配置读取
  - 基本概念
    - 命令
      - 每一行开始第一个单词.
      - 一个模块可以对应多个命令. 
        - http/server/location, 都可以有本模块的命令.
        - 如果一个命令在多个block下，需要merge. 
          - merge 就是根据父配置决定子配置. 
            - server需要从http merge. 
            - location需要从server merge
            - nested location 也需要从上级merge.
          - 例如: server/location 下的都有同一个命令，但是参数不同，这时候就需要merge来决定，以决定哪个block拥有优先级.
    - 参数
      - 命令之后，‘;'之前称为参数.
    - block
      - '{}'之间称为block.
      - 一个block又可以包含多个block. 
        > 例如server包含多个location.
    - conf_ctx
      - 四级指针: 'void ****';
      - cycle->conf_ctx是配置的核心成员, 所有配置都保存在这个指针里.
      - 层级关系.
        - core
          - http
            - ngx_http_core_ctx_t  
            - server
              - location
            - upstream
            - map
          - stream
      - core
        - 指向长度为ngx_max_module的(void *)数组，数组里的东西各模块不同。
        - 只有core_module才会非空. 例如http/log/event等，他们的模块类型为'NGX_CORE_MODULE'
      - http
        - 获得所有模块http级别的配置.
          - cycle->conf_ctx[ngx_http_module.index]->main_conf
          - http-core 模块
            - ngx_http_core_main_conf_t
            - 里面包含里server数组, 指向server配置. 每个server的配置为ngx_http_core_srv_conf_t
      - server
        - 获得所有模块在某个server的配置.
          - cycle->conf_ctx[ngx_http_module.index]->main_conf[ngx_http_core_module.ctx_index]->servers[n]->srv_conf
          - http-core 模块
            - ngx_http_core_srv_conf_t
            - 里面包含里location的双指针.
      - location
        - 长度: ngx_http_max_module
  - 配置读取函数
     - char *(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
       - cf
         - 输入参数
         - 当前命令的数据表示
           - args->elts[0]
             > 命令
           - args->elts[1] ...
             > 参数
       - cmd
         - 指向此命令的定义
       - conf
         - 输出参数
         - 模块所对应的配置块的指针
         - 例如: ngx_http_xxx_loc_conf_t
         - 上级调用会将此配置块指针放在指定位置.
     - ngx_conf_parse
       - parse一个新文件
       - parse一个'{}'所表示的block
     - ngx_conf_handler
       - ngx_conf_parse出一行命令，会调用此函数.
       - 初始化此命令行的数据结构.
       - 调用命令行处理函数，执行此命令.
     - 调用栈分析
       - ngx_conf_parse 
         > 读取整个配置文件.
         - ngx_conf_handler 
           > 找到http命令,初始化
           - ngx_http_block
             > 读取http块的配置.
             - ngx_conf_parse
               > 继续读取http {} block的配置.
               - ngx_conf_handler
                 > 找到server的命令，初始化.
                 - ngx_http_core_server
                   > 读取server的配置.
                   - ngx_conf_parse
                     > 读取server {} block的配置
                     - ngx_conf_handler
                       > 找到location块
                       - ngx_conf_parse
                         > 读取location块的配置.
                         - ngx_conf_handler
                           > 找到utm命令.
                           - ngx_http_utm 
                             > 读取utm命令.
         
       ```
       #0  ngx_http_utm (cf=0x7fffffffe050, cmd=0x7359e0 <ngx_http_utm_commands>, conf=0x17f4420)
         at ./src/ext/ngx_http_utm_module/src/ngx_http_utm_module.c:479
       #1  0x000000000042a761 in ngx_conf_handler (last=0, cf=0x7fffffffe050) at src/core/ngx_conf_file.c:463
       #2  ngx_conf_parse (cf=cf@entry=0x7fffffffe050, filename=filename@entry=0x0) at src/core/ngx_conf_file.c:319
       #3  0x0000000000450175 in ngx_http_core_location (cf=0x7fffffffe050, cmd=<optimized out>, dummy=<optimized out>) at src/http/ngx_http_core_module.c:3080
       #4  0x000000000042a761 in ngx_conf_handler (last=1, cf=0x7fffffffe050) at src/core/ngx_conf_file.c:463
       #5  ngx_conf_parse (cf=cf@entry=0x7fffffffe050, filename=filename@entry=0x0) at src/core/ngx_conf_file.c:319
       #6  0x0000000000450c29 in ngx_http_core_server (cf=0x7fffffffe050, cmd=<optimized out>, dummy=<optimized out>) at src/http/ngx_http_core_module.c:2837
       #7  0x000000000042a761 in ngx_conf_handler (last=1, cf=0x7fffffffe050) at src/core/ngx_conf_file.c:463
       #8  ngx_conf_parse (cf=cf@entry=0x7fffffffe050, filename=filename@entry=0x0) at src/core/ngx_conf_file.c:319
       #9  0x000000000044b12d in ngx_http_block (cf=0x7fffffffe050, cmd=<optimized out>, conf=<optimized out>) at src/http/ngx_http.c:237
       #10 0x000000000042a761 in ngx_conf_handler (last=1, cf=0x7fffffffe050) at src/core/ngx_conf_file.c:463
       #11 ngx_conf_parse (cf=cf@entry=0x7fffffffe050, filename=filename@entry=0x78d2a0) at src/core/ngx_conf_file.c:319
       #12 0x0000000000427d49 in ngx_init_cycle (old_cycle=old_cycle@entry=0x7fffffffe210) at src/core/ngx_cycle.c:275
       #13 0x000000000041618a in main (argc=<optimized out>, argv=<optimized out>) at src/core/nginx.c:311
       ```
### nginx启动/处理流程
  - 读配置.
  - 建立监听端口.
    - ngx_http_add_listening
      - 设置handler处理函数 ngx_http_init_connection
    - ngx_open_listening_sockets
      - create & bind socket
    - ngx_configure_listening_sockets
      - 设置接收/发送buffer的大小.
      - 设置keepalive
      - listen socket
    - 启动子进程
      - ngx_epoll_add_event
        > 将accept事件挂载到事件列表中.
    - ngx_process_events_and_timers
      - ngx_epoll_process_events
        - ngx_event_accept
          - ngx_http_init_connection
            > 初始化连接，并设置read event的handler是 ngx_http_wait_request_handler
        - read事件
          - ngx_http_wait_request_handler
            - 创建ngx_http_request_t.
            - 将read event的handler设置为ngx_http_process_request_line.
            - ngx_http_process_request_line.
              - ngx_http_parse_request_line
                > 将read event设置为 ngx_http_process_request_headers
                - ngx_http_process_request_headers
                  - ngx_http_process_request
                    - ngx_http_handler
                        - 到nginx_http_handler处，一个请求就已经解析出来了.
                        - subrequest所产生的请求，会同样经过ngx_http_handler处理. 
                          - 后序找配置，rewrite等都是同样的流程.
                      - ngx_http_core_run_phases
                        - ngx_http_core_content_phase

### nginx全局状态图.
  - 按事件中断划分的状态机。
    - 准备知识
      - ngx_event_t 
        - handler, 每个不同状态的事件都会有相应的handler进行处理.
        - data，会随着不同的状态传入不同的值. 
    - init
      - 初始化状态，将read event的data设置为ngx_listening_t.
      - ngx_event_t
        - event_handler = ngx_event_accept
        - data = ngx_connections_t (不是普通的connection，而是listen socket所对应的connections).
    - accept
      - tcp连接成功.
      - ngx_get_connection 生成一个连接.
      - 调用ngx_listening_t->handler(ngx_http_init_connection)生成http连接.
        - ngx_http_init_connection会调用ngx_handle_read_event将rev加入到监听队列中.
      - ngx_event_t
        - event_handler = ngx_http_wait_request_handler
        - data = ngx_connection_t
    - wait_request状态.
      - handler
        - ngx_http_wait_request_handler
        - ngx_http_empty_handler
      - 处理http请求.
      - 调用ngx_http_process_request_line进入http连接处理状态.
        - ngx_http_create_request 创建http_request请求数据结构.
    - request line 状态.
      - handler
        - ngx_http_process_request_line
        - ngx_http_empty_handler
      - 读request header. 
      - 如果请求头是分片到达，则可能被中断.
    - request handler 状态.
      - 中断. 
        - ngx_http_core_run_phases.
        - ngx_http_read_client_request_body_handler/discard_body
        - ngx_http_limit_req_delay
        - r->read_event_handler.
      - handler
        - ngx_http_request_handler
          - r->read_event_handler->ngx_http_read_client_request_body_handler
        - ngx_http_request_handler
          - ngx_http_core_run_phases
            > 如果被写事件阻塞，那么重新进入core_run_phases. 例如，被access认证中断?
      - 处理报文体. 不同的location会有不同的body处理方式，有丢弃，有转发.
      - 可能被报文体中断.
    - upstream 状态. 
      - handler
        - ngx_http_upstream_handler
        - ngx_http_upstream_handler
      - 处理upstream报文状态。
      - 可能被upstream的发送和接收中断.
  - pipe line处理.
    - nginx upstream并不具备pipe-line的并行处理能力。
      - 理想模式
        - 当收到两个连续的request时，立马将两个request同时转发到upstream.
        - 将收到的response，按先后顺序送回client.
      - 实际模式.
        - 当收到两个连续的request时，对第一个req建立一个upstream，发送到server.
        - 收到server-response，送回client。
        - 对第二个req再建立一个upstream发送给upstream server. 
        - 收到server-response，送回client。
        - 两个连接，两个upstream. 
         
### nginx filter
  - body filter 和header filter是在产生响应后，并在发回client之前. 
    - 调用关系
      - ngx_http_static_handler
        - ngx_http_send_header
          - ngx_http_top_header_filter
        - ngx_http_output_filter
          - ngx_http_top_body_filter
            > 在一个请求过程中，这个函数可能会被调用很多次，如果所有的chain都没有置'last'标志，则后续仍会调用body_filter.
      - 由此可见，top_body_filter是在handler处理完之后被调用.
    - 和upstream的关系
      - upstream在调用完input_filter之后，会调用ngx_event_pipe_write_to_downstream, 并调用ngx_http_output_filter
      - 对于有upstream的时候，input_filter在前. ngx_http_top_body_filter调用在后.
    > 例如： 转发时若需要修改报文头content_length，则需要在header filter里进行.  
    > 如果要对报文进行改变，则应该在body filter里进行.    
    > body filter 会传入ngx_chain_t。 指向待输出的buffer.    
    > header filter 会传入ngx_http_request_t. 如果需要修改content length, 则需要在headers_out里进行修改.
  - upstream模块同样需要配置一个input filter. 这个filter在报文头已经收到并解析，但是报文体还在接收时.
    > 参见ngx_http_proxy_module.c
  - filter模块注册必须放在模块post_configuration回调函数里
    - 因为ngx_http_top_header_filter是在post_configuration里初始化的.
    - 如果放在command/preconfiguration里，初始化不起作用.
  - filter类型
    - header_filter
      - header/body_filter的顺序是和ngx_modules里注册顺序相反的.
      - ngx_http_top_header_filter(ngx_http_send_header函数内调用)
      - ngx_http_not_modified_header_filter
      - ngx_http_headers_filter 
        > 注意后面有一个header_filter
      - ngx_http_userid_filter
      - ngx_http_charset_header_filter
      - ngx_http_ssi_header_filter
      - ngx_http_gzip_header_filter
      - ngx_http_range_header_filter
      - ngx_http_chunked_header_filter
      - ngx_http_header_filter
        > 注意前面有一个ngx_http_headers_filter
      - ngx_http_write_filter
        > ngx_http_write_filter将报文写出去. 

    - body_filter
      - ngx_http_range_body_filter
      - ngx_http_copy_filter
      - 自定义的filter. 
      - ngx_http_charset_body_filter
      - ngx_http_ssi_body_filter
      - ngx_http_postpone_filter
      - ngx_http_gzip_body_filter
      - ngx_http_chunked_body_filter
      - ngx_http_write_filter
    - request body filter.
      - ngx_http_request_body_save_filter
    - upstream input filter.

### upstream 处理流程
  - 负载均衡
    - 加权round_robin
      > [算法链接](https://blog.csdn.net/zhangskd/article/details/50194069) ***非常经典***
    - least_conn
      > 最少连接的server优先.
    - ip_hash
      - 算法思路
        - 计算所有ip_server的权重之和.
        - 根据源ip，计算hash = hash(int)% total_weight.
        - 遍历所有的peer，如果hash> weight, 则，hash=hash-weight. 直到找到一个weight大于hash的peer为止.
      - 可以将同一个台主机绑定到同一台服务器上. 
        > 如果client是nat模式，而且源ip由可能变，则这种方式会出现问题. 应对方式是cookie_hash
    - url_hash
      - 根据url进行hash，相同的url会映射到同一个server上, 能搞提高server的缓存利用率.
    - cookie_hash
      - 根据cookie hash到不同的server上。由于一个用户的用户id cookie在一段时间内保持恒定. 根据cookie hash可以将用户绑定到特定的服务器上. 
    - fair
      - 根据每个请求的处理速度计算, 比加权轮询更加智能.
      
  - ngx_http_proxy_handler
    - ngx_http_upstream_create
    - ngx_http_read_client_request_body
      - ngx_http_upstream_init.    ====> upstream的启动函数, 进入它之后，所有的后续流程都将自动化进行，用户模块可以无需关心.
        - ngx_http_upstream_init_request
          - uscf->peer.init
            - ngx_http_upstream_init_ip_hash_peer
          - ngx_http_upstream_connect
            - ngx_event_connect_peer
              > r->upstream.peer.get 获得正确的peer地址.
            - ngx_http_upstream_send_request
              - ngx_http_upstream_send_request_body
              - ngx_http_upstream_process_header
                - ngx_http_upstream_process_body_in_memory
  - 从上述代码中可以看出，upstream设计的就是一层套一层的流水线模式. 初始化报文头, 发送报文，处理报文头，处理报文体. 
  - 每一级函数都可以被socket中断. 当socket的条件得以满足时会继续后续流程. 
  
### subrequest 处理流程.
  - subrequest被整合成一个树状结构.
  - 发送subrequest是按作树的后序遍历. 例如:
    > sub11->sub12->sub21->sub22
  - ngx_http_next_body_filter
    - 这个函数会在后序链表(ngx_http_postpone_filter)里会将自身添加到r->postponed队列.
    - 在它之前调用ngx_http_subrequest会排在当前request之前.
    - 在它之后调用的会排在之后.

### nginx事件
  - nginx 是事件驱动型设计，无阻塞模型.
  - 容器式编程(类似于面向对象的继承), 支持:
    - epoll
      - ngx_connect_t 里包含read和write事件队列
    - poll
    - select
  - nginx在如何将http的流程接上，费了很大的功夫，相关的代码也晦涩难懂.
    - r->connection->read/write->handler会指定当前状态的回调函数，从这个函数进去之后，会继续一个http的后续流程. 
      > 例如ngx_http_request_handler 函数. 
  - nginx惊群问题
    - 原因
      - nginx master process 会创建listening socket.
      - 多个worker thread会监听listening socket.
      - 如果多个worker thread同时监听，那么当一个tcp 连接建立时，会唤醒所有的worker process.
    - 解决方案.
      - 跨进程mutex.
        - 每个work thread会尝试取得accept锁.
        - 如果取得accept锁，则将listen socket的fd加入到读队列. 
          - 否则，如果此进程上次获得过此锁，则将listen socket的锁移除出读队列.
        - 通过这种方式，保证每次都只有一个worker-thread监听listen socket.
    - accept event block问题.
      - nginx需要处理大量的http流量，从而导致accept事件得不到及时处理.
      - 解决办法.
        - 读取事件并不真正的处理，而是将事件存入ngx_posted_events. 这样所有事件能非常快速的执行完
        - 当所有accept事件处理完成之后，再处理ngx_posted_events.
        - 如果worker thread并非accept event的获取者，则可以直接在ngx_process_events里直接处理事件.

      

    
### HTTP 处理
  - 快速索引
    - server
      > 通配hash算法
    - location
      > 平衡二叉树.
  - http请求处理的11个阶段
    - 定义在ngx_http_core_main_conf_t里. 
    - 在http_module ctx定义的post 函数里，可以添加自己的处理函数.
      ```
      ngx_http_handler_pt *h;
      ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
      h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
      if (h == NULL) {
          return NGX_ERROR;
      }
      *h = ngx_http_hello_world_post_read_phase_handler;
      ```
### upstream
  - 相关命令
    - proxy_pass
    - proxy_redirect
    - proxy_store
      > 
    - proxy_bind
      > 将连接upstream的地址绑定为制定地址.
  - upstream的三种处理方式
    - 不转发上游响应.
      - subrequest可能要用到，因为我们需要修改上游响应.
    - 上游网速快
    - 下游网速快
  - proxy_pass
    - ngx_http_proxy_pass
      > 读取配置信息，并改变ngx_http_core_module的处理函数. 
    - ngx_http_proxy_handler
      - ngx_http_upstream_create, 
      - 设立upstream相关的回调函数.
        - create_request
        - process_header
        - abort/reinit request
        - finalize_request
        - input_filter
  
    - ngx_http_read_client_request_body
      > 读取整个请求报文.
      - 最后调用ngx_http_upstream_init
        - create_request callback
          > proxy 模块，create request就是创建/修改相应的http请求.   
          > 例如: 正常http1.1连接的connection时keep-alive的，但是proxy要求，connection需要改成close. 这是rfc的规定.
        - ngx_http_upstream_connect
          - 设置回调
            ```
            c->write->handler = ngx_http_upstream_handler;
            c->read->handler = ngx_http_upstream_handler;

            u->write_event_handler = ngx_http_upstream_send_request_handler;
            u->read_event_handler = ngx_http_upstream_process_header;
            ```
            - 通过这个回调的设定，下次当有upstream的响应到达时，系统就可以正确的恢复执行.
            - nginx的所有现场恢复都是通过这四个回调函数进行的.
            - write/read是大的阶段。write_event_handler/read_event_handler是小的阶段.
            - 注意write_event_handler是upstream的.
          - ngx_http_upstream_send_request
            - ngx_http_upstream_process_header
   - proxy_cache
    - [nginx的cache机制](https://blog.csdn.net/weiyuefei/article/details/35295117)
    - 将proxy到的内容cache到本地, 如果下次代理同样的uri，就直接从cache里去内容。
      - proxy_cache 打开时会启动两个cache管理的进程. 
      - cache manager process和nginx worker process共享内存. 
      - 如果需要打开一个新的文件，worker会将一个cache描述符加入到共享内存里. 
      - cache manger 会读取这个描述符队列, 并将这个描述符中所对应的buf chain写到文件里.
      - 由于cache manager的存在，worker process不会再进行文件的读写操作，相关文件交由cache manager去完成. 
        - worker thread只往共享队列里添加描述符. 性能非常高.
        - proxy cache和open_file_cache不一样. 
          - 静态文件默认情况下是由sendfile交由内存完成发送.
          - 再gzip打开的时候，会通过pread读取, 注意这个操作是阻塞的. 所有一般都需要为静态文件配置缓存，以提高性能. 

      ```
      nobody    1920  0.0  0.0  34780  2720 ?        S    18:21   0:00 nginx: cache manager process
      nobody    1921  0.0  0.0  34780  2720 ?        S    18:21   0:00 nginx: cache loader process
      ```
      - 多个worker-thread之间会以共享内存的方式访问cache.
    - 实例:
      ```
        proxy_cache_path /usr/local/nginx/html/cache levels=1:2 keys_zone=cache_one:1m inactive=1d max_size=30g;
        location ~ ^/av_redirect/(.*)/(.*)$ {
            resolver 172.29.151.60;

            #proxy_pass和proxy_cache必须在同级目录下
            proxy_pass http://$1/$2;
            proxy_cache_key $host$uri$args;
            proxy_cache cache_one;
            proxy_cache_valid 200 1d;
            proxy_cache_valid any 1m;
        }

      ```

### sub request
  - 相关函数
    - ngx_http_subrequest
      > 创建一个链接，此时并没有将请求发出去.
      - ngx_http_post_request
    - ngx_http_send_special
    - ngx_http_run_posted_requests
    
    
### 数据结构
  - nginx hash
    - ngx_hash_t 
      - 不同与普通的hash表，它是一开始就知道了元素的key.
        > 普通的hash表是无法使用这种结构的. 
      - 不是以链表的形式，而是以内存块偏移的形式进行组织.
        - 所有bucket都指向同一片内存（偏移不同).
        - 通过连续内存，提高性能.
      - 实例:
        - 解析http header
          - 通过header name找到ngx_http_header_t
          - 此结构保存此header name在ngx_http_request_t中的偏移.
          - 通过handler执行相关处理函数.
            - 如host, 会hook上正确的virtual server.
        
    - ngx_hash_combined_t 
      - 支持前/后通配符匹配. 实际上是查找三次.   
        - 精确匹配  
        - 前通配符匹配.
        - 后通配符匹配.
      - server的查找使用的是这种方式.
      - 参考连接:
        > https://www.cnblogs.com/0x2D-0x22/p/4139805.html
      
  - nginx 内存池
    - ngx_pool_t
    - 将多次的malloc汇聚成一次大片的malloc
      - 优点
        - 从而减少malloc的次数，
        - 减少内存碎片，提高整体性能.
        - 避免内存泄漏. 
      - 缺点
        - 内存浪费，是一种以空间换时间的做法.
      - 适用范围
        - 在一个生命周期内，如处理一个http请求时，中间会有多次内存的申请的情况, 能极大提升效率.
        - 如果在生命周期内，可以提前释放的部分，最好不用memory pool的方式. 
        - 不定长度的申请，能极大程度的减少内存碎片.
        - 非常适用于容易产生内存泄漏的地方. 
    - 和objcache比较.
      - objcache比较适用于定长的申请和释放, memory pool适用于不定长的申请.
      - memory pool更使用于一个生命周期(如session)内都存在的内存段, objcache更适用于短期使用的. 
      
### nginx phase handler
  - [参考文章](https://blog.csdn.net/liujiyong7/article/details/38817135)
  - phase是存在main_conf里，意味着，对任何location都生效。
  - phase最后会被合成一个数组，但这个数组的下标和phase不见的是一样的。一个phase可能对应几个数组元素。
  - phase handler的返回值非常关键. 
    - decline 表示继续下一个handler.
    - ok, 继续下一个phase.
    - done/again. 表示遇到阻塞,把控制权交由epoll模块，等待下一次调度.
  - phase handler定义了处理报文的几个步骤
  - ngx_http_handler
    - ngx_http_core_generic_phase 0
      - 默认没有挂载
    - ngx_http_core_rewrite_phase 1 
      - ngx_http_rewrite_handler
        > server块中的rewrite
    - ngx_http_core_find_config_phase 2
    - ngx_http_core_rewrite_phase 3 
      - ngx_http_rewrite_handler
        > location块中的rewrite
    - ngx_http_core_post_rewrite_phase 4 
    - ngx_http_core_generic_phase 5
      - ngx_http_limit_req_handler
    - ngx_http_core_generic_phase 6 
      - ngx_http_limit_conn_handler 
    - ngx_http_core_access_phase 7
      - ngx_http_access_handler
    - ngx_http_core_access_phase 8
      - ngx_http_auth_basic_handler
    - ngx_http_core_post_access_phase 9
      - 暂时没有挂载
    - ngx_http_core_content_phase 10 
      > 如果r->content_handler, 则不会调用后续的phase handler. 这意味着content_handler & phase_handler只有一个能生效. 
      - ngx_http_index_handler
    - ngx_http_core_content_phase 11
      - ngx_http_autoindex_handler
    - ngx_http_autoindex_handler 12
      - ngx_http_static_handler
        - ngx_http_send_header
        - ngx_http_output_filter
  ```
  (gdb) p *ph
  $23 = {checker = 0x42a51c <ngx_http_core_generic_phase>, handler = 0x46d069   <ngx_http_hello_world_post_read_phase_handler>, next = 1}
  (gdb) p ph[0].checker
  $24 = (ngx_http_phase_handler_pt) 0x42a51c <ngx_http_core_generic_phase>
  (gdb) p ph[1].checker
  $25 = (ngx_http_phase_handler_pt) 0x42a584 <ngx_http_core_rewrite_phase>
  (gdb) p ph[1]
  $26 = {checker = 0x42a584 <ngx_http_core_rewrite_phase>, handler = 0x45a6f3 <ngx_http_rewrite_handler>, next = 2}
  (gdb) p ph[2]
  $27 = {checker = 0x42aa0f <ngx_http_core_find_config_phase>, handler = 0x0, next = 0}
  (gdb) p ph[3]
  $28 = {checker = 0x42a584 <ngx_http_core_rewrite_phase>, handler = 0x45a6f3 <ngx_http_rewrite_handler>, next = 4}
  (gdb) p ph[4]
  $29 = {checker = 0x42a5bf <ngx_http_core_post_rewrite_phase>, handler = 0x0, next = 2}
  (gdb) p ph[5]
  $30 = {checker = 0x42a51c <ngx_http_core_generic_phase>, handler = 0x455f85 <ngx_http_limit_req_handler>, next = 7}
  (gdb) p ph[6]
  $31 = {checker = 0x42a51c <ngx_http_core_generic_phase>, handler = 0x4554ac <ngx_http_limit_conn_handler>, next = 7}
  (gdb) p ph[7]
  $32 = {checker = 0x42a676 <ngx_http_core_access_phase>, handler = 0x454aa9 <ngx_http_access_handler>, next = 10}
  (gdb) p ph[8]
  $33 = {checker = 0x42a676 <ngx_http_core_access_phase>, handler = 0x4544d8 <ngx_http_auth_basic_handler>, next = 10}
  (gdb) p ph[9]
  $34 = {checker = 0x42a77c <ngx_http_core_post_access_phase>, handler = 0x0, next = 10}
  (gdb) p ph[10]
  $35 = {checker = 0x42b488 <ngx_http_core_content_phase>, handler = 0x445275 <ngx_http_index_handler>, next = 13}
  (gdb) p ph[11]
  $36 = {checker = 0x42b488 <ngx_http_core_content_phase>, handler = 0x452fd8 <ngx_http_autoindex_handler>, next = 13}
  (gdb) p ph[12]
  $37 = {checker = 0x42b488 <ngx_http_core_content_phase>, handler = 0x444a5a <ngx_http_static_handler>, next = 13}
  (gdb) p ph[13]
  $38 = {checker = 0x0, handler = 0x50000002, next = 0}
  (gdb)
  ```
  

### ngxin 脚本引擎和变量
  - nginx 脚本兼容pcre.
    - perl.
    - 支持正则表达式.
    - rewrite 只能能直接对url进行重写.
      - 模式匹配
        - 取值
          > ()内的值将通过$1, $2...进行返回.   
        - ~ 表示对uri进行模式匹配.
        - (.+?) 表示贪婪查找.
        - (.*)表示非贪婪查找结果.
        - 
        ```
             location /av_download {
            resolver 172.29.151.60;
            set $a "args is: $args\n";

            if ($arg_target ~ ^(.+?)/(.*)$) {
                set $b "非贪婪查找结果:$2\n";
            }

            if ($arg_target ~ ^(.*)/(.*)$) {
                set $c "贪婪查找结果:$2\n";
            }
            echo "\n$a\n$b\n$c\n";            
        }
        curl http://192.168.101.2/av_download?target=www.sohu.com/a/b/279837212_260616?_f=index_chan08news_6

        args is: target=www.sohu.com/a/b/279837212_260616?_f=index_chan08news_6

        非贪婪查找结果:a/b/279837212_260616?_f=index_chan08news_6

        贪婪查找结果:279837212_260616?_f=index_chan08news_6
        ```
  - nginx内部的脚本也是通过command来实现的.
    - set $file "index.html" 
      - 解析这个配置的时候，就会通过"ngx_http_rewrite_set"来进行处理。处理流程如下:
        - 检查变量字段是不是以$开头
        - 将变量加入到cmcf->variables_keys中, 而且是changable的. 
          - 为什么要放入main的配置中, 而不是loc的配置中??? 
            > 因为变量的定义是整个main结构所见的.
          > 为什么需要添加？？不应该是在模块的preconfiguration中就已经添加了变量么？？？
          > 如果没有经过set 语句，就不会加入到variables_keys中，后续使用就会报错.
        - 获取变量的下标.
        - 根据loc的配置，执行相应的script. 
    - 系统会将一行脚本编译成ngx_http_script_value_code_t’存入ngx_http_rewrite_loc_conf_t->codes中. 
      - 脚本由一系列字符串组成, 可以分成多个执行块（执行块不定长）.
        - 每个执行块都以函数指针开头.
        - 后续跟执行此函数需要的变量.
        - 每次进入函数指针所指的函数时，会将codes的当前位置进行偏移, 便宜的大小由当前函数所对应的数据结构决定. 

          ```
          set $user_name jack;
          set $key_not_found abcd
          ```
          > 上述一段代码，最终rewrite模块编译出的codes如下:
            ```
            (gdb) p *(ngx_http_script_value_code_t *)((char *)rlcf->codes->elts)
            $58 = {code = 0x442850 <ngx_http_script_value_code>, value = 0, text_len = 4, text_data = 7201071}
            (gdb) p sizeof(ngx_http_script_value_code_t)
            $59 = 32
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+32)
            $60 = (ngx_http_script_code_pt) 0x4429ae <ngx_http_script_var_set_handler_code>
            (gdb) p sizeof(ngx_http_script_var_handler_code_t)
            $61 = 24
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+24)
            $62 = (ngx_http_script_code_pt) 0x6de12f
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+24+32)
            $63 = (ngx_http_script_code_pt) 0x442850 <ngx_http_script_value_code>
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+32+24+32)
            $64 = (ngx_http_script_code_pt) 0x4428bb <ngx_http_script_set_var_code>
            (gdb) p *(ngx_http_script_code_pt *)(rlcf->codes->elts+32+24+32+24)
            $65 = (ngx_http_script_code_pt) 0x0
            ```

  - 内部变量
    - 模块内部已经定义的变量. 
      > 通过ngx_http_variables_t所定义的.
    
    ```
    在nginx.conf中
    if ($http_user_agent ~ MIME) {
      rewrite ^(.*)$ /mise/$1 break;
    }
    ```
  - 外部变量
    - 用户自己定义的变量 
      > set语句所定义的.
    ```
    ```
  - 特殊变量
    - $arg_xxx/$cookie_xxx
      > 如: $arg_class表示url问号后所代表的参数.  
      > 它其实也是一个变量，在cmcf里占一个位置。它的处理程序就是读取url，并把相应的变量解析出来， 性能不如正常的变量.  
  - 变量共享
    > 变量的生命周期，同一个主请求内.   
    > 需要特别注意的是，如果两个location下对同一个变量赋值，而且会出现跳转，或者子请求到另一个location时，变量就会被覆盖。  
  - 相应步骤:
    - 所有可能用到的变量都在preconfiguration里添加到main_conf->variables_keys里.  
    - 读取配置的时候，如果遇到相应的变量，则从main_conf->variables_keys里查找，是否存在.  
      > 脚本 set 所对应的操作，会用到ngx_http_variables_t->set_handler函数，如果这个值将会更改，则需要定义相应的set_handler.  
      > NGX_HTTP_REWRITE_PHASE的回调函数ngx_http_rewrite_handler会触发脚本的执行.   
    - 在所需要的阶段赋值, 配置阶段或者连接处理阶段都可以.
  - ngx_http_variables_add_core_vars
  - ngx_http_variables_t
    > 所有变量，都通过variables进行定义.  
  - ngx_variables_value_t
  - ngx_http_complex_value
    > 这个函数可以获得复杂脚本表达式的值. ngx_http_set_complex_value_slot可以进行读取脚本表达式.  
  - 执行顺序
    ```
      set $file index1.html;
      index $file;
      set $file index2.html;
    ```
    - 上述配置会最终重定向到indext2.html. 
      - rewrite phase
        - 步骤1. file=index1.html.
        - 步骤2. file=index2.html.
      - content phase
        - 步骤1. 冲定向到file, 结果显示index2.html.

### nginx 进程间通信
  - 基本方式.
    - signal
      - 临时进程向master进程发送相应的signal, master进程接着执行相应动作.
        - nginx -s quit
          - nginx临时进程会发送一个SIGQUIT 消息给master进程.
          - 临时进程直接退出.
          - master进程收到消息后，通过socketpair/channel向其下所有worker发送NGX_CMD_QUIT消息
      - master进程也会通过这种方式向子进程发送信号. 例如channel发送失败时. 或者SIGWINCH时
    - socketpair
      - master向worker thread发送NGX_CMD_QUIT/NGX_CMD_TERM/NGX_CMD_REOPEN消息.
  - 多进程操作.
    - 配置升级.
      - 主进程释放老配置。
      - 将新配置从新读取到内存中.
      - fork新的worker thread.
      - 向老进程发送winchg信号，老进程不再处理新连接。处理完成后，就退出。
      - master进程不变. 共享内存不变。
    - 应用程序升级
      - echo "必须确认nginx启动命令是/usr/sbin/nginx -c /usr/local/nginx/conf/nginx.conf, 否则会报错"
      - 步骤:
        1. kill -USR2 `cat /usr/local/nginx/logs/nginx.pid`
        2. sleep 10
          > "等待新进程up..."
        3. kill -WINCH `cat /usr/local/nginx/logs/nginx.pid.oldbin`
          > "停止worker process 接受新连接..."
        4. sleep 3
        5. kill -QUIT `cat /usr/local/nginx/logs/nginx.pid.oldbin`
          >  old master process 退出
      - 注意事项:
        1. 配置升级并非一个命令就全部完成.
          > 这样做的目的是，如果新版本出现问题，用户可以撤销升级.
        2. 当kill -USR2 pid 之后，新老版本存在两个master, 两组worker.
          - 新版本master相应nginx -s ...命令.
          - 新/老版本worker共同处理流量.
        3. 必须主动手动停止老版本的worker/master
        4. 如果在停止worker之后发现新版本有问题，nginx -s quit可以退出新版本。并再生成老版本worker.

### nginx 文件操作.
  - 
### nginx 日志切割
  - 为什么要切割日志？
    > 一般Nginx安装好后有些人会打开日志记录，有些人会关闭日志记录，打开日志记录的人一般都会把架设在Nginx上的所有网站日志都存在同一个文件里（比如我存在access.log日志文件里），这样日积月累所有网站的访问记录就会把日志文件越积越大，当需要查看日志文件的时候一看就是一大串，不方便查找。现在，如果我把每天的日志文件分割开来用相应的日期标识出来这样就大大方便查找了。 我是建议打开日志记录，日志记录里面存放着很多有用的东西。比如：浏览器名称，可以方便你对网站的排版做出调整；IP地址，如果网站收到攻击，你就可以查到那个IP地址。 Linux下我们可以简单的把日志文件mv走，但是你会发现mv走后新的日志文件没有重新生成，一般linux下用的文件句柄，文件被打开情况下你mv走文件，但是原来操作这个文件的进程还是有这个文件的inode等信息，原进程还是读写原来的文件，因此简单的mv是无法生效的。
  - 因此建议过程如下
    1. mv原文件到新文件目录中，这个时候 nginx还写这个文件（写入新位置文件中了）
    2. 调用nginx -s  reopen用来打开日志文件，这样nginx会把新日志信息写入这个新的文件中

  - 这样完成了日志的切割工作，同时切割过程中没有日志的丢失。

### nginx 时间管理
 - ngx time 模块实现要点:
   - 原理
     - ngx的事件管理模块是由read/write构成.
     - 为避免频发的系统调用，ngx 时间通过缓存进行管理.
       - 缓存分为64个时间缓存slot.
       - write 负责更新时间. 并将 ngx_cached_time 移动到下一个slot.
       - read 读取ngx_cached_time所指向的时间.
     - 可能存在多个writer更新时间, 所以write有锁.
     - 时间字符串在每次更新时间时都会缓存, 供log 等其他模块使用
     - ngx_time_update 在每个event 循环里都会进行调用
   - [参考文档](https://blog.csdn.net/Mrzhangjwei/article/details/77150335)

### nginx 文件操作.
  - AIO
    - AIO 背后的基本思想是允许进程发起很多 I/O 操作，而不用阻塞或等待任何操作完成。
    - 稍后或在接收到 I/O 操作完成的通知时，进程就可以检索 I/O 操作的结果。
    - aio默认通过eventfd实现，也可以通过thread-pool来实现.
    - eventfd 原理
      - nginx aio是通过eventfd来实现的.
      - 通过epoll监控eventfd，就能监听eventfd所关联的事件.
        - read
          - 通过SYS_io_submit将FD挂入eventFD的监听队列.
          - 事件到达时，event FD就能够得到通知。
          - ngx_epoll_eventfd_handler通过io_getevents就能获得事件和事件相关的pvt data.
  - sendfile
    - 绕过userspace, 直接发送整个文件给对方.
    - TODO：是不是也可以用来接收文件???
  - directio
    - 绕过内核内存空间，直接DMA到用户内存空间.
    - 适合大文件的操作. 小文件适合用sendfile
    - 实例
      > 如上典型的配置中，文件大小小于8M采用 send file。大于8M采用directio的多线程异步IO
          ```
          location /video/ {
              sendfile       on;
              aio            on;
              directio       8m;
          }
          ```
  - open file cache.
    - 将openfile的FD缓存起来，以实现文件快速打开和关闭，节约系统资源。
  - read ahead
    - 在打开FD时，就load文件内容。也就是文件的预取.
    - POSIX_FADV_SEQUENTIAL

### nginx TCP socket 
  - 惊群问题.
    - 多个worker 进程监听在同一个fd上，如果一个新连接到来, 内核会唤醒所有被accept阻塞的进程.
      - 无效调度会显著增加.
    - 解决办法.
      - accept lock.
        - 每个worker thread只有抓住accept lock, 才能监听accept事件.
  - SO_REUSEADDR
    - 如果在一个socket绑定到某一地址和端口之前设置了其SO_REUSEADDR的属性，那么除非本socket与产生了尝试与另一个socket绑定到完全相同的源地址和源端口组合的冲突，否则的话这个socket就可以成功的绑定这个地址端口对。这听起来似乎和之前一样。但是其中的关键字是完全。SO_REUSEADDR主要改变了系统对待通配符IP地址冲突的方式。
    - 如果不用SO_REUSEADDR的话，如果我们将socketA绑定到0.0.0.0:21，那么任何将本机其他socket绑定到端口21的举动（如绑定到192.168.1.1:21）都会导致EADDRINUSE错误。因为0.0.0.0是一个通配符IP地址，意味着任意一个IP地址，所以任何其他本机上的IP地址都被系统认为已被占用。如果设置了SO_REUSEADDR选项，因为0.0.0.0:21和192.168.1.1:21并不是完全相同的地址端口对（其中一个是通配符IP地址，另一个是一个本机的具体IP地址），所以这样的绑定是可以成功的。需要注意的是，无论socketA和socketB初始化的顺序如何，只要设置了SO_REUSEADDR，绑定都会成功；而只要没有设置SO_REUSEADDR，绑定都不会成功。
    - [参考链接](://blog.csdn.net/yaokai_assultmaster/article/details/68951150)
  - reuse port选项.
    - 多个worker进程, 可以绑定同一个监听端口.
    - 内核实现调度，不会出现惊群问题.
    - 可以用来解决惊群问题.
  - TCP_FASTOPEN
    - TCP 快速打开选项.
    - 可以在客户端未发送最后ack之前就发送数据.
    - [参考链接](https://baike.baidu.com/item/TCP%E5%BF%AB%E9%80%9F%E6%89%93%E5%BC%80/22748901?fr=aladdin)
  - defer accept 选项.
    - 服务器端设置defer accept
      - 只有收到数据时才会唤醒被accept阻塞的nginx服务器。通过这种方式，减少一次服务器的调度时间.
    - 客户端设置defer accept，
      - ack回随数据一起发送出去，从而省掉一次ack的传送时延.
    - [参考链接](https://blog.csdn.net/for_tech/article/details/54175571)
  - linger close 选项.
    - 延迟关闭. 
    - 内核关闭socket的行为
      - read buffer 不为空，发送rst. 丢弃write buffer数据。
        - 如果content phase之前出错，发送错误给客户端, 此时read buffer数据不为空. 客户端无法获取错误信息.
      - read buffer 为空, 等待write buffer数据发送完毕。4此分手，关闭socket.
    - [参考链接](https://blog.csdn.net/wangpengqi/article/details/17245889)
  - backlog size
    - 设置linux 内核tcp backlog queue的大小.
  - keepalive 
    - interval/cnt/time.
  - SO_SNDLOWAT/SO_RCVLOWAT
    - SO_RCVLOWAT和SO_SNDLOWAT选项分别表示TCP接收缓冲区和发送缓冲区的低水位标记。它们一般被I/O复用系统调用用来判断socket是否可读或可写。
    - 当TCP接收缓冲区中可读数据的总数大于其低水位标记时，I/O复用系统调用将通知应用程序可以从对应的socket上读取数据；
    - 当TCP发送缓冲区中的空闲空间（可以写入数据的空间）大于其低水位标记时，I/O复用系统调用将通知应用程序可以往对应的socket上写入数据。
    - 其作用和postpone_output命令一样。
  - TCP_NODELAY
    - 关闭或者开启nagle算法.
  - TCP_CORK
    - TCP_NOPUSH in windows.
    - 增强版本的nagle算法，阻塞小包.
  - IP_RECVDSTADDR
    - UDP 报文选项.
    - 在recvmsg函数调用时，能够返回对端ip地址, 以便socket进行区分.
  - IP_PKTINFO
    - UDP 报文选项.
    - 在recvmsg/sendmsg时，会发送in_pktinfo数据结构.

### SSL 流程
  - ngx_http_add_listening 时设置tcp accept连接.
    - ngx_http_init_connection 时设置设置rev->handler = ngx_http_ssl_handshake
  - sni 解析
    - 在多个server共享一台server时，通过sni可以使得SSL连接时能够获取到正确的证书.
    - 设置openssl的sni callback为ngx_http_find_virtual_server

### 调用栈
  ```
  (gdb) bt
  #0  ngx_http_hello_world_handler (r=0x6b0120) at ./src/ext/ngx_http_hello_world_module/ngx_http_hello_world_module.c:56
  #1  0x000000000042b467 in ngx_http_core_content_phase (r=0x6b0120, ph=<optimized out>) at src/http/ngx_http_core_module.c:1363
  #2  0x00000000004263d0 in ngx_http_core_run_phases (r=r@entry=0x6b0120) at src/http/ngx_http_core_module.c:840
  #3  0x00000000004264e9 in ngx_http_handler (r=r@entry=0x6b0120) at src/http/ngx_http_core_module.c:823
  #4  0x000000000042e30d in ngx_http_process_request (r=r@entry=0x6b0120) at src/http/ngx_http_request.c:1911
  #5  0x000000000043041a in ngx_http_process_request_headers (rev=rev@entry=0x6c3ec0) at src/http/ngx_http_request.c:1342
  #6  0x00000000004306e7 in ngx_http_process_request_line (rev=rev@entry=0x6c3ec0) at src/http/ngx_http_request.c:1022
  #7  0x0000000000430e05 in ngx_http_wait_request_handler (rev=0x6c3ec0) at src/http/ngx_http_request.c:499
  #8  0x00000000004232a6 in ngx_epoll_process_events (cycle=<optimized out>, timer=<optimized out>, flags=<optimized out>)
      at src/event/modules/ngx_epoll_module.c:822
  #9  0x000000000041b8d4 in ngx_process_events_and_timers (cycle=cycle@entry=0x6b2920) at src/event/ngx_event.c:242
  #10 0x0000000000421437 in ngx_worker_process_cycle (cycle=cycle@entry=0x6b2920, data=data@entry=0x0) at src/os/unix/ngx_process_cycle.c:753
  #11 0x000000000041fed6 in ngx_spawn_process (cycle=cycle@entry=0x6b2920, proc=proc@entry=0x4213b6 <ngx_worker_process_cycle>, data=data@entry=0x0,
      name=name@entry=0x4711f6 "worker process", respawn=respawn@entry=-4) at src/os/unix/ngx_process.c:198
  #12 0x000000000042159f in ngx_start_worker_processes (cycle=cycle@entry=0x6b2920, n=1, type=type@entry=-4) at src/os/unix/ngx_process_cycle.c:358
  #13 0x0000000000422495 in ngx_master_process_cycle (cycle=0x6b2920, cycle@entry=0x6ae910) at src/os/unix/ngx_process_cycle.c:243
  #14 0x0000000000404458 in main (argc=<optimized out>, argv=<optimized out>) at src/core/nginx.c:359
  (gdb)
  ```
### 调优.
- 负载不均衡.
  - 默认nginx并不是很均衡. 在开启mutex on之后，负载才会变得均衡.
- sysctl
  - 增大文件描述符
    - ulimit -n 999999
      - 将进程的文件描述符增大.
  - 增大backlog队列
    - 当打小文件测试时，backlog队列太小，系统会将其视作syn-flood攻击. 
    - syn backlog
      - net.ipv4.tcp_max_syn_backlog = 100000
    - 网卡backlog
      - net.core.netdev_max_backlog = 1000
  - 缩短fin-wait时间
    - 如果不缩短这个时间，tcp客户端的60000万个端口将很快被用光，从而导致连接建立不起来.
    - net.ipv4.tcp_fin_timeout = 2
  - RPS/RFS
    - 这个能帮助系统提高cache命中率.
  - LRO
    - 网卡能将TCP报文聚合，例如(data + fin两片报文可以被聚合成一片，送往服务器),从而提升服务器的性能.
    - ethtool -K eth0 查看.

### 参考文献
  [Nginx如何解决惊群效应](https://blog.csdn.net/wan_hust/article/details/38958545)
