
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "funcscope.h"

/*****************************************************************/

#define FS_MAX_LINE 512

#ifndef HUGETLBFS_MAGIC
#define HUGETLBFS_MAGIC 0x958458f6
#endif

/*****************************************************************/

funcscope_runtime_t g_funcscope_rt = {
    .mmap_addr = NULL,
    .funcscope = NULL,
    .mmap_fd = -1,
    .server_fd = -1,
    .initialized = 0,
};

/*****************************************************************/

/**
 * @brief 再次确认 fs 的类型
 * @param path HugePage 挂载的绝对路径
 * @return 失败返回 0，成功返回 1
 */
static int fs_is_hugetlbfs(const char *path)
{
    struct statfs st;
    if (statfs(path, &st) < 0)
        return 0;
    return st.f_type == HUGETLBFS_MAGIC;
}

/**
 * @brief 尝试 mmap 一个最小 hugepage，成功 => 当前进程“可以使用” hugepage
 * @param dir HugePage 挂载的绝对路径
 * @return 失败返回 0，成功返回 1
 */
static int fs_try_mmap_hugepage(const char *dir)
{
    char file[256];

    snprintf(file, sizeof(file), "%s/huge_test_%d", dir, getpid());

    int fd = open(file, O_CREAT | O_RDWR, 0600);
    if (fd < 0)
        return 0;

    /* 不需要 ftruncate，hugetlbfs 会自动对齐 hugepage */
    void *addr = mmap(NULL,
                      2 * 1024 * 1024, /* 最小 2MB */
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED,
                      fd,
                      0);

    int ok = (addr != MAP_FAILED);

    if (ok)
        munmap(addr, 2 * 1024 * 1024);

    close(fd);
    unlink(file);
    return ok;
}

/**
 * @brief HugePage 可用性检测
 * @param found_dir 返回参数，存放 hugepage 的挂载点
 * @param len 描述 found_dir 指向内存空间的大小
 * @return 失败返回 0，成功返回 1
 */
int fs_detect_hugepage(char *found_dir, size_t len)
{
    FILE *fp = fopen("/proc/self/mounts", "r");

    if (!fp) return 1;

    char line[FS_MAX_LINE];

    while (fgets(line, sizeof(line), fp))
    {
        char dev[128], mnt[128], type[64];

        if (sscanf(line, "%127s %127s %63s", dev, mnt, type) != 3)
            continue;

        if (strcmp(type, "hugetlbfs") != 0)
            continue;

        /* 再次确认 fs 类型 */
        if (!fs_is_hugetlbfs(mnt))
            continue;

        /* 尝试 mmap，作为最终裁决 */
        if (fs_try_mmap_hugepage(mnt))
        {
            strncpy(found_dir, mnt, len);
            fclose(fp);
            return 1; /* 可以使用 hugepage */
        }
    }

    fclose(fp);
    return 0; /* 不可用 */
}

/*****************************************************************/

#define HUGEPAGE_SIZE   (2UL * 1024 * 1024)

/* 向上对齐到 2MB */
static inline size_t fs_round_up_2mb(size_t size)
{
    return (size + HUGEPAGE_SIZE - 1) & ~(HUGEPAGE_SIZE - 1);
}

/**
 * @brief hugetlbfs mmap
 * @param huge_dir : hugetlbfs 挂载路径，例如 "/mnt/huge"
 * @param map_size : 期望映射大小（字节）
 * @param out_path : 返回实际使用的文件路径（可选，可为 NULL）
 * @param out_path_len : out_path 空间大小
 * @return 返回映射后的地址
 */
void * funcscope_hugepage_mmap(const char *huge_dir, size_t map_size)
{
    char path[PATH_MAX];
    int fd;
    void *addr;
    size_t aligned_size;

    if (!huge_dir || map_size == 0)
    {
        errno = EINVAL;
        return MAP_FAILED;
    }

    aligned_size = fs_round_up_2mb(map_size);

    /* 自动生成文件名（示例：funcscope_<pid>.map） */
    snprintf(path, sizeof(path), "%s/funcscope_%d.map", huge_dir, getpid());

    fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0)
    {
        perror("open hugepage file failed");
        return MAP_FAILED;
    }

    /* hugepage 文件大小必须是 hugepage 对齐 */
    if (ftruncate(fd, aligned_size) < 0)
    {
        perror("ftruncate failed");
        close(fd);
        unlink(path);
        return MAP_FAILED;
    }

    addr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED)
    {
        perror("mmap failed");
        return MAP_FAILED;
    }

    g_funcscope_rt.mmap_fd = fd;

    close(fd);
    unlink(path);

    /* 清零，避免读取历史内容 */
    memset(addr, 0, aligned_size);

    return addr;
}

/*****************************************************************/

#define PAGE_4K 4096UL
#define ALIGN_4K(x) (((x) + PAGE_4K - 1) & ~(PAGE_4K - 1))

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static int is_tmpfs(const char *path)
{
    struct statfs s;
    return (statfs(path, &s) == 0 && s.f_type == TMPFS_MAGIC);
}

const char *funcscope_pick_file_mmap_dir(char *buf, size_t len)
{
    if (is_tmpfs("/dev/shm"))
    {
        snprintf(buf, len, "/dev/shm");
        return buf;
    }

    if (is_tmpfs("/run"))
    {
        snprintf(buf, len, "/run");
        return buf;
    }

    snprintf(buf, len, "/tmp");
    return buf;
}

/**
 * @brief file mmap
 * @param dir :  挂载路径，例如 "/dev/shm"
 * @param map_size : 期望映射大小（字节）
 * @param out_path : 返回实际使用的文件路径（可选，可为 NULL）
 * @param out_path_len : out_path 空间大小
 * @return 返回映射后的地址
 */
void *funcscope_file_mmap_4K(const char *dir, size_t map_size)
{
    int fd = -1;
    void *addr = MAP_FAILED;
    size_t aligned_size;
    char path[256];
    pid_t pid;

    if (!dir || map_size == 0)
        return MAP_FAILED;

    /* 4K 对齐 */
    aligned_size = ALIGN_4K(map_size);

    pid = getpid();

    /* 自动生成文件名（示例：funcscope_<pid>.map） */
    snprintf(path, sizeof(path), "%s/funcscope_%d.map", dir, pid);

    /* 确保目录存在（只创建一级，失败可忽略） */
    mkdir(dir, 0755);

    fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0)
    {
        perror("open file mmap");
        goto fail;
    }

    /* 必须调整文件大小 */
    if (ftruncate(fd, aligned_size) < 0)
    {
        perror("ftruncate file mmap");
        goto fail;
    }

    addr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED)
    {
        perror("mmap file");
        goto fail;
    }

    g_funcscope_rt.mmap_fd = fd;

    close(fd);
    unlink(path);
    //fd = -1;

    /* 清零，避免读取历史内容 */
    memset(addr, 0, aligned_size);

    return addr;

fail:
    if (fd >= 0) {
        close(fd);
        unlink(path);
    }
    return MAP_FAILED;
}

/*****************************************************************/

#define SERVER_SOCK_FMT "/tmp/funcscope.%d.sock"
#define MAX_PENDING_CONN 4

/**
 * @brief 初始化 Unix Domain Socket server
 * @return server fd，失败返回 -1
 */
int funcscope_server_init(void)
{
    int sockfd;
    struct sockaddr_un addr;

    sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), SERVER_SOCK_FMT, getpid());

    // 如果 socket 文件存在，删除
    unlink(addr.sun_path);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, MAX_PENDING_CONN) < 0)
    {
        perror("listen");
        close(sockfd);
        return -1;
    }

    printf("Funcscope server listening on %s\n", addr.sun_path);
    return sockfd;
}

/*****************************************************************/

/**
 * @brief 在被检测的进程中调用该函数初始化资源
 * @param num_checkpoints 需要被监测点的数量，最大支持的监测点的数量是 128 个
 * @param level 取值来自于 enum funcscope_level
 * @return 失败返回 0，成功返回 1
 */
int32_t funcscope_caller_initialize(uint8_t num_checkpoints, int32_t level)
{

    char dir[128] = {0};

    if (num_checkpoints <= 0)
        return 0;

    if (num_checkpoints > FUNCSCOPE_CHECK_POINTS)
        return 0;

    if (!(level <= FS_FULL && level >= FS_LITE && ((level & (level - 1)) == 0)))
        return 0;

    size_t size = sizeof(funcscope_t) + num_checkpoints * level * sizeof(uint64_t);

    if (fs_detect_hugepage(dir, 128))
    {
        g_funcscope_rt.mmap_addr = funcscope_hugepage_mmap(dir, size);
        size = fs_round_up_2mb(size);
    }
    else
    {
        funcscope_pick_file_mmap_dir(dir, 128);
        g_funcscope_rt.mmap_addr = funcscope_file_mmap_4K(dir, size);
        size = ALIGN_4K(size);
    }

    if (g_funcscope_rt.mmap_addr == MAP_FAILED) return 0;

    g_funcscope_rt.server_fd = funcscope_server_init();

    if (g_funcscope_rt.server_fd == -1) return 0;

    g_funcscope_rt.initialized = 1;

    funcscope_t *funcscope = (funcscope_t *)(g_funcscope_rt.mmap_addr);

    funcscope->private.level = level;
    funcscope->private.num_checkpoints = num_checkpoints;
    funcscope->private.space_size = (uint32_t)size;
    funcscope->private.monitoring_process_exit = 0;

    uint8_t *base = (uint8_t *)g_funcscope_rt.mmap_addr + sizeof(funcscope_t);

    int i = 0;
    for (i = 0; i < num_checkpoints; i++) {
        funcscope->slots[i].write_pos = 0;
        funcscope->slots[i].level = level;
        funcscope->slots[i].address = (uint64_t *)(base + i * level * sizeof(uint64_t));
    }

    g_funcscope_rt.funcscope = funcscope;

    return 1;
}

/**
 * @brief 非阻塞轮询 Unix socket，并在 tool attach 时发送 mmap backing fd
 *
 * @note 该函数设计用于放入主循环（热路径）中调用：
 *       - 无 tool 连接时，仅执行一次非阻塞 accept，立即返回
 *       - 无内存分配、无锁、无阻塞
 *       - 对业务性能影响可忽略
 *
 * @return 1 表示成功向某个 tool 发送了 fd
 *         0 表示本次无 tool attach
 *        -1 表示发生错误（可忽略或记录）
 */
int funcscope_server_poll_and_send_fd(void)
{
    int connfd;
    struct msghdr msg = {0};
    struct iovec iov;
    char dummy = 0;

    if (!(g_funcscope_rt.initialized))
        return 0;

    /* server 未初始化或 mmap 未就绪，直接返回 */
    if (g_funcscope_rt.server_fd < 0 || g_funcscope_rt.mmap_fd < 0)
        return 0;

    /* 非阻塞 accept：无连接时立即返回 */
    connfd = accept(g_funcscope_rt.server_fd, NULL, NULL);
    if (connfd < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }

    /* 构造最小消息，仅用于携带 fd */
    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    *((int *)CMSG_DATA(cmsg)) = g_funcscope_rt.mmap_fd;

    /* 发送 fd（一次系统调用） */
    if (sendmsg(connfd, &msg, 0) < 0)
    {
        close(connfd);
        return -1;
    }

    close(connfd);
    return 1;
}

/**
 * @brief 在被检测的进程中调用该接口清理资源
 */
int32_t funcscope_caller_cleanup(void)
{

    if (!g_funcscope_rt.initialized) return 0;

    funcscope_t *fs = g_funcscope_rt.funcscope;

    /* 1. 设置一个“关闭标志”，通知工具进程 */
    fs->private.monitoring_process_exit = 1;

    /* 2. 内存屏障，保证工具进程可见 */
    __sync_synchronize();

    /* 3. munmap 自己 */
    munmap(g_funcscope_rt.mmap_addr, fs->private.space_size);

    g_funcscope_rt.initialized = 0;
    g_funcscope_rt.mmap_addr = NULL;

    return 1;
}

/*****************************************************************/