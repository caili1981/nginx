### nginx 
ngx_unix_recv


### 调用栈
#0  ngx_http_output_filter (r=r@entry=0x31eaea0, in=in@entry=0x7ffe833753e8) at src/http/ngx_http_core_module.c:1770  
#1  0x00000000004abad6 in ngx_http_send_response (r=0x31eaea0, status=200, ct=ct@entry=0x0, cv=0x2fea418) at  src/http/ngx_http_core_module.c:1742  
#2  0x00000000004b8f1f in ngx_http_script_return_code (e=0x31ebae8) at src/http/ngx_http_script.c:1399  
#3  0x00000000004d40de in ngx_http_rewrite_handler (r=0x31eaea0) at src/http/modules/ngx_http_rewrite_module.c:180  
#4  0x00000000004aafa4 in ngx_http_core_rewrite_phase (r=0x31eaea0, ph=<optimized out>) at src/http/ngx_http_core_module.c:921  
#5  0x00000000004a7b01 in ngx_http_core_run_phases (r=r@entry=0x31eaea0) at src/http/ngx_http_core_module.c:867  
#6  0x00000000004a7bd5 in ngx_http_handler (r=r@entry=0x31eaea0) at src/http/ngx_http_core_module.c:850  
#7  0x00000000004ae1c2 in ngx_http_process_request (r=r@entry=0x31eaea0) at src/http/ngx_http_request.c:2055  
#8  0x00000000004afd74 in ngx_http_process_request_headers (rev=rev@entry=0x7f03380830f0) at src/http/ngx_http_request.c:1480  
#9  0x00000000004b0034 in ngx_http_process_request_line (rev=0x7f03380830f0) at src/http/ngx_http_request.c:1151  
#10 0x00000000004a41f9 in ngx_kqueue_process_events (cycle=0x2fcd180, timer=<optimized out>, flags=1) at src/event/modules/ngx_kqueue_module.c:693  
#11 0x000000000049c0d7 in ngx_process_events (flags=1, timer=<optimized out>, cycle=0x2fcd180) at src/event/ngx_event.h:454  
#12 ngx_process_events_and_timers (cycle=cycle@entry=0x2fcd180) at src/event/ngx_event.c:258  
#13 0x00000000004a1535 in ngx_worker_process_cycle_loop (arg=0x2fcd180) at src/os/unix/ngx_process_cycle.c:912  
#14 0x00000000005b64f8 in main_loop ()  
#15 0x0000000000621c6b in rte_eal_mp_remote_launch ()  
#16 0x00000000005b93c4 in ff_dpdk_run ()  
#17 0x00000000004a0a70 in ngx_spawn_process (cycle=cycle@entry=0x2fcd180, proc=proc@entry=0x4a20a8 <ngx_worker_process_cycle>, data=data@entry=0x0,
    name=name@entry=0xa82c14 "worker process", respawn=respawn@entry=-3) at src/os/unix/ngx_process.c:199  
#18 0x00000000004a1a19 in ngx_start_worker_processes (cycle=cycle@entry=0x2fcd180, n=1, type=type@entry=-3) at src/os/unix/ngx_process_cycle.c:500  
#19 0x00000000004a26c8 in ngx_master_process_cycle (cycle=0x2fcd180) at src/os/unix/ngx_process_cycle.c:145  
#20 0x000000000047b8fa in main (argc=<optimized out>, argv=<optimized out>) at src/core/nginx.c:402  
