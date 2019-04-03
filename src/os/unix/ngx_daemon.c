
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t
ngx_daemon(ngx_log_t *log)
{
    int  fd;

    switch (fork()) {
    case -1:
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "fork() failed");
        return NGX_ERROR;

    case 0:
        break;

    default:
        exit(0);  /* 父进程退出，子进程继续运行, 从而避免挂起控制终端 */
    }

    /* 子进程 */
    ngx_parent = ngx_pid;
    ngx_pid = ngx_getpid();

    /*  
        首先我们要了解一些基本概念：

        进程组 ：

        每个进程也属于一个进程组
        每个进程主都有一个进程组号，该号等于该进程组组长的PID号 .
        一个进程只能为它自己或子进程设置进程组ID号
        会话期：

        会话期(session)是一个或多个进程组的集合。

        setsid()函数可以建立一个对话期：

         如果，调用setsid的进程不是一个进程组的组长，此函数创建一个新的会话期。

         (1)此进程变成该对话期的首进程

         (2)此进程变成一个新进程组的组长进程。

         (3)此进程没有控制终端，如果在调用setsid前，该进程有控制终端，那么与该终端的联系被解除。 如果该进程是一个进程组的组长，此函数返回错误。

         (4)为了保证这一点，我们先调用fork()然后exit()，此时只有子进程在运行

         现在我们来给出创建守护进程所需步骤：

         编写守护进程的一般步骤步骤：

         （1）在父进程中执行fork并exit推出；

         （2）在子进程中调用setsid函数创建新的会话；

         （3）在子进程中调用chdir函数，让根目录 ”/” 成为子进程的工作目录；

         （4）在子进程中调用umask函数，设置进程的umask为0；

         （5）在子进程中关闭任何不需要的文件描述符
         */
    if (setsid() == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "setsid() failed");
        return NGX_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "open(\"/dev/null\") failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDIN) failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDOUT) failed");
        return NGX_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
