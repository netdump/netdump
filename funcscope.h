

#ifndef __FUNCSCOPE_H__
#define __FUNCSCOPE_H__

#include <stdint.h>

/*
FS_LITE（128 点）轻量级采样

每个函数作用域最多记录 128 个时间点

适合：
    快速定位问题
    对整体趋势有大致判断
特点：
    记录信息较少
    对程序运行行为影响极小

推荐场景：
    默认开启
    长时间运行的在线环境

FS_NORMAL（256 点）标准采样

每个函数作用域最多记录 256 个时间点

适合：
    常规性能分析
    比较不同函数或不同版本的差异

特点：
    信息量与可读性平衡
    不会改变程序的整体性能特征

推荐场景：
    日常分析
    问题复现与验证

FS_DEEP（512 点）深度采样

每个函数作用域最多记录 512 个时间点

适合：
    观察短时间内的性能波动
    分析尾延迟、突发抖动

特点：
    能捕获更细粒度的变化
    适合结合图表或时间序列查看

推荐场景：
    定向分析某一热点路径
    问题已基本定位，需要进一步细化

FS_FULL（1024 点）高密度采样

每个函数作用域最多记录 1024 个时间点

适合：
    捕获极短时间内的异常行为
    分析瞬时抖动、极端尾延迟

特点：
    信息最完整
    在低频读取（500ms / 1s）模式下，对程序执行路径影响可忽略

推荐场景：
    专项分析
    问题复现窗口较短的场景

=============================================================================
重要说明（请务必阅读）

    采样密度越高 ≠ 程序越慢
    采样密度仅决定“可记录的信息数量”，不会改变函数本身的执行逻辑。

    读取频率决定整体扰动水平
    在默认的低频读取模式（500ms 或 1s）下，各采样等级均不会对程序造成可观测的性能影响。

    不确定如何选择时
    建议使用 FS_NORMAL（256），在绝大多数场景下都能提供足够的信息。
=============================================================================

一句话选型指南

    想看趋势 → FS_LITE

    日常分析 → FS_NORMAL

    查抖动 / 尾延迟 → FS_DEEP

    抓瞬时异常 → FS_FULL

=============================================================================
*/

/* funcscope 采样密度等级（采样点数量） */
enum funcscope_level
{
    FS_LITE = 128,   /* 轻量级采样，开销极低 */
    FS_NORMAL = 256, /* 标准采样等级，适合常规使用 */
    FS_DEEP = 512,   /* 深度采样，用于更细粒度分析 */
    FS_FULL = 1024,  /* 最大采样密度，适用于低频读取（500ms/1s），对被测路径扰动可忽略 */
};

#define FUNCSCOPE_CHECK_POINTS 128

#define FUNCSCOPE_CACHELINE_SIZE 64

#if defined(__GNUC__) || defined(__clang__)
#define FUNCSCOPE_CACHELINE_ALIGNED \
    __attribute__((aligned(FUNCSCOPE_CACHELINE_SIZE)))
#else
#error "Unsupported compiler"
#endif

#define FUNCSCOPE_CACHELINE_PAD(sz) ((sz) < FUNCSCOPE_CACHELINE_SIZE ? (FUNCSCOPE_CACHELINE_SIZE - (sz)) : 0)

typedef struct FUNCSCOPE_CACHELINE_ALIGNED funcscope_priv
{
    int32_t level;
    int32_t num_checkpoints;
    uint32_t space_size;
    uint32_t monitoring_process_exit;
    char padding[FUNCSCOPE_CACHELINE_PAD(2 * sizeof(int32_t) + 2 * sizeof(uint32_t))];
} funcscope_priv_t;

typedef struct FUNCSCOPE_CACHELINE_ALIGNED funcscope_slot
{
    /* ================== hot fields (write-only) ================== */

    uint64_t write_pos; /* 当前写位置（单进程 / 单线程递增） */
    uint32_t level;     /* ring size，必须是 2 的幂 */
    uint32_t _pad0;     /* 显式 padding，保证 8 字节对齐 */

    uint64_t *address; /* 指向采样 ring buffer（mmap 区域） */

    /* ================== cacheline padding ================== */

    char _pad1[FUNCSCOPE_CACHELINE_SIZE - sizeof(uint64_t) /* write_pos */
               - sizeof(uint32_t)                          /* level */
               - sizeof(uint32_t)                          /* _pad0 */
               - sizeof(uint64_t *)                        /* address */
    ];
} funcscope_slot_t;

typedef struct FUNCSCOPE_CACHELINE_ALIGNED funcscope
{
    funcscope_priv_t private;

    /* 128 个监测点，write_pos + address 连续存放，cache friendly */
    funcscope_slot_t slots[FUNCSCOPE_CHECK_POINTS];

    char func_name[FUNCSCOPE_CHECK_POINTS][64];
} funcscope_t;

typedef struct FUNCSCOPE_CACHELINE_ALIGNED funcscope_runtime
{
    /* mmap 后的起始虚拟地址（owner 进程私有） */
    void *mmap_addr;

    funcscope_t *funcscope;

    /* mmap backing 文件的 fd（普通文件 / 巨页文件 / memfd） */
    int mmap_fd;

    /* Unix Domain Socket server fd，用于 tool attach */
    int server_fd;

    /* funcscope 是否已成功初始化 1: 初始化完成，可安全使用 0: 未初始化或初始化失败 */
    int32_t initialized;

} funcscope_runtime_t;

extern struct funcscope_runtime g_funcscope_rt;

/**
 * @brief 在被检测的进程中调用该函数初始化资源
 * @param num_checkpoints 需要被监测点的数量，最大支持的监测点的数量是 128 个
 * @param level 取值来自于 enum funcscope_level
 * @return 失败返回 0，成功返回 1
 */
int32_t funcscope_caller_initialize(uint8_t num_checkpoints, int32_t level);


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
int funcscope_server_poll_and_send_fd(void);

/**
 * @brief 以固定频率（每 N 次）非阻塞轮询 funcscope tool attach，并在需要时发送 mmap fd
 *
 * 该宏用于在业务主循环或高频路径中，低成本地周期性调用
 * funcscope_server_poll_and_send_fd()，用于支持运行时 tool attach。
 *
 * 设计目标：
 *  - 无锁
 *  - 无内存分配
 *  - 非阻塞
 *  - 热路径开销极低
 *
 * 实现说明：
 *  - 宏内部维护一个 static 计数器 __fs_poll_cnt
 *  - 每次展开调用时自动自增
 *  - 仅当 (__fs_poll_cnt & (N - 1)) == 0 时才触发真正的 poll
 *
 * 重要约束：
 *  - N 必须是 2 的幂（例如 8 / 64 / 1024）
 *  - 这是为了使用按位与 (&) 实现取余判断，避免除法指令
 *
 * 使用注意：
 *  - 每一个宏“展开点”拥有独立的计数器
 *  - 不同函数 / 不同源文件互不干扰
 *  - 不适合在多个线程共享同一个展开点
 *
 * 示例：
 *
 *   for (;;) {
 *       FUNCSCOPE_SERVER_POLL_EVERY_N(1024);
 *       do_work();
 *   }
 */
#define IS_POWER_OF_2(x) (((x) & ((x) - 1)) == 0)

#define FUNCSCOPE_SERVER_POLL_EVERY_N(N)          \
    do                                            \
    {                                             \
        static unsigned int __fs_poll_cnt;        \
        assert(IS_POWER_OF_2(N));                 \
        if (((__fs_poll_cnt++) & ((N) - 1)) == 0) \
        {                                         \
            funcscope_server_poll_and_send_fd();  \
        }                                         \
    } while (0)

/**
 * @brief 在被检测的进程中调用该接口清理资源
 */
int32_t funcscope_caller_cleanup(void);


#ifdef __x86_64__
/**
 * @brief x86 平台读取 TSC（Time Stamp Counter）
 * @return CPU tick / cycle
 */
static inline uint64_t funcscope_rdtsc(void)
{
    uint32_t hi, lo;

    // CPUID 序列化保证顺序
    __asm__ __volatile__(
        "cpuid\n\t" // 序列化
        "rdtsc\n\t" // 读取 TSC
        : "=a"(lo), "=d"(hi)
        : "a"(0)
        : "rbx", "rcx");

    return ((uint64_t)hi << 32) | lo;
}

#elif defined(__aarch64__)
/**
 * @brief ARMv8 平台读取 EL0 单调计数器 CNTVCT_EL0
 * @return CPU tick / counter
 */
static inline uint64_t funcscope_rdtsc(void)
{
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

#else
#error "Unsupported platform"
#endif

#define FUNCSCOPE_ENTER(idx)                                \
    uint64_t __fs_start_##idx = 0;                          \
    do {                                                    \
        __builtin_expect(g_funcscope_rt.initialized, 1)     \
            ? (__fs_start_##idx = funcscope_rdtsc()) : 0;   \
    } while(0);


#define FUNCSCOPE_EXIT(idx)                                                   \
    do                                                                        \
    {                                                                         \
        if (__builtin_expect(g_funcscope_rt.initialized, 1))                  \
        {                                                                     \
            funcscope_slot_t *__slot = &g_funcscope_rt.funcscope->slots[idx]; \
            uint64_t __tsc_end = funcscope_rdtsc();                           \
            uint64_t __delta = __tsc_end - __fs_start_##idx;                  \
            uint64_t __pos = __slot->write_pos++;                             \
            __slot->address[__pos & (__slot->level - 1)] = __delta;           \
        }                                                                     \
    } while (0)

#define FUNCSCOPE_EXIT_FAST(idx)                                          \
    do                                                                    \
    {                                                                     \
        funcscope_slot_t *__slot = &g_funcscope_rt.funcscope->slots[idx]; \
        uint64_t __tsc_end = funcscope_rdtsc();                           \
        uint64_t __delta = __tsc_end - __fs_start_##idx;                  \
        uint64_t __pos = __slot->write_pos++;                             \
        __slot->address[__pos & (__slot->level - 1)] = __delta;           \
    } while (0)

#endif