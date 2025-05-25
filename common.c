/**
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <linux/version.h>
#include "trace.h"
#include "common.h"


/**
 * @brief 
 *  Global process number
 */
uint32_t GCOREID = 0;


/**
 * @brief 
 *  Array storing the pid value of the child process
 */
pid_t childpid[3] = {0, 0, 0};


/**
 * @brief 
 *  Check if the kernel version is greater than 2.6.6 
 * @note
 *  If the kernel version is less than 2.6.6, 
 *  the program will exit because the program uses mq_open and other related APIs.
 */
void nd_check_kernel_version(void) {

    if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 6)) {
        fprintf(stderr, "Kernel version is less than 2.6.6\n");
        exit(1);
    }
    return ;
}


/**
 * @brief 
 * 	It is to page align the incoming address addr
 * @param addr 
 * 	 Addresses that need to be aligned
 * @return 
 * 	Returns a page-aligned address
 */
uintptr_t align_address(uintptr_t addr)
{
	TC("Called { %s(%p)", __func__, (void*)(addr));

    long page_size = sysconf(_SC_PAGESIZE); 

    if (unlikely(page_size == -1)) {
		TE("%s", strerror(errno));
        page_size = 4096;
	}

    #if 0
    long page_size = (1 << 21);
    #endif

    RULong(((addr + page_size - 1) & ~(page_size - 1)));
}


/**
 * @brief 
 *  Check if the directory exists and create it if it does not exist
 * @param fpath
 *  File path pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int nd_check_directory(const char *fpath) {

    TC("Called { %s(%p)", __func__, fpath);

    struct stat statbuf;
    if (unlikely(((stat(fpath, &statbuf)) == -1))) {
        if (unlikely((mkdir(fpath, 0755)) == -1)) {
            TE("%s", strerror(errno));
            RInt(ND_ERR);
        }
        TI("directory created: %s", fpath);
    } else if (S_ISDIR(statbuf.st_mode)) {
        TI("directory exists: %s", fpath);
    } else {
        TI("Path exists but is not a directory: %s", fpath);
        RInt(ND_ERR);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the file exists, and delete it if it does exist
 * @param file
 *  File name pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int check_and_delete_file(const char *fname) {

    TC("Called { %s(%p)", __func__, fname);

    if (access(fname, F_OK) == 0) {  
        if (unlikely(unlink(fname) == 0)) {
            TI("File deleted: %s", fname);
        } else {
            TE("%s", strerror(errno));
            RInt(ND_ERR);
        }
    } else {
        TI("File does not exist: %s", fname);
    }

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the directory is writable
 * @param fpath
 *  File path pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int check_directory_writable(const char *fpath) {

    TC("Called { %s(%p)", __func__, fpath);

    if (unlikely((access(fpath, W_OK)) != 0)) {
        TE("%s", strerror(errno));
        RInt(ND_ERR);
    }

    TI("directory is writable %s", fpath);

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the directory is readable
 * @param fpath
 *  File path pointer
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static int check_directory_readable(const char *fpath) {

    TC("Called { %s(%p)", __func__, fpath);

    if (unlikely((access(fpath, R_OK) != 0))) {
        TE("%s", strerror(errno));
        RInt(ND_ERR);
    }

    TI("directory is readable: %s", fpath);

    RInt(ND_OK);
}


/**
 * @brief 
 *  Check if the directory containing the file name exists; 
 *  Check if the directory containing the file name is writable; 
 *  Check if the directory containing the file name is readable; 
 *  Delete the file if it exists
 * @param fname
 *  The file name to be checked
 * @return
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int nd_check_fpath (char * fname) {

    TC("Called { %s(%p)", __func__, fname);

    char fpath[COMM_NAMESIZE];
    strncpy(fpath, fname, sizeof(fpath));

    char * slash = strrchr(fpath, '/');
    if (slash != NULL) { 
        *slash = '\0';
    } 
    else { 
        fpath[0] = '.';
        fpath[1] = '\0';
    }

    if (unlikely((nd_check_directory(fpath)) == ND_ERR)) 
        RInt(ND_ERR);

    if (unlikely((check_and_delete_file(fname)) == ND_ERR))
        RInt(ND_ERR);

    if (unlikely((check_directory_writable(fpath)) == ND_ERR))
        RInt(ND_ERR);

    if (unlikely((check_directory_readable(fpath)) == ND_ERR))
        RInt(ND_ERR);

    RInt(ND_OK);
}


/** =========================================================================================== */
#if 0

/**
 * @brief The code between the dividing lines is about hugepage.
 */


/**
 * @brief
 *  Stores the raw values in the transparent large page configuration file
 */
char nd_thp_original[64] = {0};


/**
 * @brief
 *  A sign of whether the transparent page has been modified
 * @note
 *  1 indicates that the configuration file of the transparent page has been modified
 *  0 indicates that the configuration file of the transparent page has not been modified
 */
unsigned int nd_thp_mod_flag = 0;


/**
 * @brief
 *  Stores the original value of the large page memory
 */
int nd_hugepage_original_numeric_value = 0;


/**
 * @brief Global storage mount point
 */
char nd_G_store_mountpoint[nd_G_store_mountpoint_space] = {0};


/**
 * @brief
 *  Set the status of transparent pages to Forbidden state
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_disable_transparent_hugepages(void)
{
    TC("Called { %s(void)", __func__);

    int fd, ret = -1;
    char tmp_thp_ret_value[64] = {0};

    memset(nd_thp_original, 0, sizeof(nd_thp_original));

    if (access(ND_THP_DISABLE_PATH, F_OK) != 0)
    {
        TE("THP control file not found, skipping disable");
        RInt(-1);
    }

    if ((fd = open(ND_THP_DISABLE_PATH, O_RDWR)) == -1)
    {
        TE("Failed to open THP control file: %s", strerror(errno));
        RInt(-1);
    }

    ssize_t len = read(fd, tmp_thp_ret_value, (sizeof(tmp_thp_ret_value) - 1));
    if (len <= 0)
    {
        TE("Failed to read THP status: %s", strerror(errno));
        goto cleanup;
    }

    tmp_thp_ret_value[(len - 1)] = '\0';

    TI("original: %s", tmp_thp_ret_value);

    char *ret1 = strchr(tmp_thp_ret_value, '[');
    char *ret2 = strchr(tmp_thp_ret_value, ']');

    strncpy(nd_thp_original, (ret1 + 1), (ret2 - ret1 - 1));
    nd_thp_original[(ret2 - ret1)] = '\0';

    TE("nd_thp_original: %s", nd_thp_original);

    if (strstr(nd_thp_original, "[never]") == NULL)
    {
        lseek(fd, 0, SEEK_SET);
        ret = write(fd, ND_THP_DISABLE_CMD_STRING, strlen(ND_THP_DISABLE_CMD_STRING));
        if (ret != strlen(ND_THP_DISABLE_CMD_STRING))
        {
            ret = -1;
            TI("Failed to disable THP: %s;[errno: %d]", strerror(errno), errno);
            goto cleanup;
        }
        nd_thp_mod_flag = 1U;
        TI("Transparent HugePages disabled (original state: %s)", nd_thp_original);
    }
    else
    {
        TI("Transparent HugePages already disabled");
    }

    ret = 0;

cleanup:

    close(fd);
    RInt(ret);
}


/**
 * @brief
 *  Restore the system's transparent large page settings
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_recover_transparent_hugepages(void)
{
    TC("Called { %s(void)", __func__);

    int ret = -1, fd = 0;

    if (!nd_thp_mod_flag)
    {
        RInt(0);
    }

    if (access(ND_THP_DISABLE_PATH, F_OK) != 0)
    {
        TE("THP control file not found, skipping disable");
        RInt(-1);
    }

    if ((fd = open(ND_THP_DISABLE_PATH, O_RDWR)) == -1)
    {
        TE("Failed to open THP control file: %s;[errno: %d]", strerror(errno), errno);
        RInt(-1);
    }

    lseek(fd, 0, SEEK_SET);
    ret = write(fd, nd_thp_original, strlen(nd_thp_original));
    TI("ret: %d; strlen(nd_thp_original): %ld", ret, strlen(nd_thp_original));
    if (ret != strlen(nd_thp_original))
    {
        ret = -1;
        TE("Failed to disable THP: %s;[errno: %d]", strerror(errno), errno);
        goto cleanup;
    }

    nd_thp_mod_flag = 1U;
    TI("Transparent HugePages recover (original state: %s)", nd_thp_original);

cleanup:

    close(fd);
    RInt(ret);
}


/**
 * @brief
 *  Compatible with the old kernel's large page count setting
 * @param pages
 *  The value that needs to be set
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_set_hugepages_legacy(int pages)
{
    TC("Called { %s(%d)", __func__, pages);

    int fd, ret = -1;
    char buf[32];

    if ((fd = open(ND_HUGEPAGE_OLD_WAY_SETUP, O_WRONLY)) == -1)
    {
        TE("[errno: %d]: %s", errno, strerror(errno));
        RInt(-1);
    }

    snprintf(buf, sizeof(buf), "%d", pages);
    if (((write(fd, buf, strlen(buf))) != (strlen(buf))))
    {
        TE("[errno: %d]: %s", errno, strerror(errno));
        goto cleanup;
    }

    ret = 0;

cleanup:
    close(fd);
    RInt(ret);
}


/**
 * @brief
 *  Compatible with large page count reads from older kernels
 * @return
 *  The amount of the original large page memory successfully returned
 *  Failure returns -1
 */
int nd_get_current_hugepages_legacy(void)
{

    TC("Called { %s(void)", __func__);

    int fd;
    char buf[32];

    if ((fd = open(ND_HUGEPAGE_OLD_WAY_SETUP, O_RDONLY)) == -1)
    {
        TE("[errno: %d]: %s", errno, strerror(errno));
        RInt(-1);
    }

    if ((read(fd, buf, sizeof(buf))) == -1)
    {
        TE("[errno: %d]: %s", errno, strerror(errno));
        RInt(-1);
    }

    if (!nd_hugepage_original_numeric_value)
    {
        nd_hugepage_original_numeric_value = atoi(buf);
    }

    RInt((atoi(buf)));
}


/**
 * @brief
 *  Use the sysfs type interface to set the large page memory
 * @param delta_pages
 *  The incremental value of the large page memory
 * @param sys_path
 *  Use the sysfs type interface to set the file path used by large page memory
 * @return
 *  Failure returns 0x7FFFFFFF
 *  When the value of parameter delta_pages is returned, it indicates complete success
 *  If the returned value is a different value, it indicates that a part of the increment has been added
 */
int nd_set_hugepages_use_sysfs_interface(int delta_pages, char *sys_path)
{

    TC("Called { %s(%d, %s)", __func__, delta_pages, sys_path);

    int fd, ret = 0x7FFFFFFF;
    int current_pages = 0, target_pages = 0;

    if ((fd = open(sys_path, O_RDWR)) == -1)
    {
        TE("[errno: %d]Failed to open %s: %s", errno, sys_path, strerror(errno));
        RInt(ret);
    }

    char buf[32];
    ssize_t len = read(fd, buf, (sizeof(buf) - 1));
    if (len <= 0)
    {
        TE("[errno: %d]Read failed: %s", errno, strerror(errno));
        goto cleanup;
    }

    buf[len] = '\0';
    nd_hugepage_original_numeric_value = current_pages = atoi(buf);
    TI("current_pages: %d", current_pages);

    target_pages = current_pages + delta_pages;
    if (target_pages < 0)
    {
        TE("Invalid target pages: %d (current=%d, delta=%d)", target_pages, current_pages, delta_pages);
        goto cleanup;
    }

    lseek(fd, 0, SEEK_SET);
    snprintf(buf, sizeof(buf), "%d", target_pages);
    if (((write(fd, buf, strlen(buf))) != (strlen(buf))))
    {
        TE("[errno: %d]Write failed: %s", errno, strerror(errno));
        goto cleanup;
    }

    lseek(fd, 0, SEEK_SET);
    memset(buf, 0, sizeof(buf));
    len = read(fd, buf, sizeof(buf) - 1);
    if (len <= 0)
    {
        TE("[errno: %d]Verification read failed: %s", errno, strerror(errno));
        goto cleanup;
    }

    buf[len] = '\0';
    int actual_pages = atoi(buf);
    TI("actual_pages: %d", actual_pages);

    if (actual_pages != target_pages)
    {
        TE("Partial success: Requested %d, got %d pages", target_pages, actual_pages);
        ret = actual_pages - current_pages; // Returns the actual increment
    }
    else
    {
        ret = delta_pages; // Totally successful
    }

cleanup:
    close(fd);
    RInt(ret);
}


/**
 * @brief
 *  Set the large page memory increment
 * @param delta_pages
 *  The incremental value of the large page memory
 * @param size
 *  The size of the large page memory
 * @return
 *  0 is returned for success
 *  -1 is returned for failure
 */
int nd_set_hugepages_incremental(int delta_pages, enum hugepage_size size)
{

    TC("Called { %s(%d, %d)", __func__, delta_pages, size);

    int ret = -1;
    char sys_path[128] = {0};

    TI("delta_pages: %d; size: %d", delta_pages, size);

    snprintf(sys_path, sizeof(sys_path), ND_HUGEPAGE_SYS_PATH_FORMAT, size);

    // Use an interface of type sysfs
    if (access(sys_path, F_OK) == 0)
    {
        ret = nd_set_hugepages_use_sysfs_interface(delta_pages, sys_path);
        TI("ret: 0x%08x\n", ret);
        if (ret == 0x7FFFFFFF)
        {
            TE("use sysfs interface set hugepage failed");
            RInt(-1);
        }
        else if (ret == delta_pages)
        {
            TI("use sysfs interface set hugepages Totally successful");
            RInt(0);
        }
        else
        {
            TI("use sysfs interface set hugepages Partially successful");
            if (ret < 0)
            {
                TI("After setting up, the number of hugepages has become smaller");
            }
            else
            {
                TI("The number of hugepages increased by %d after setting", ret);
            }
            RInt(0);
        }
    }
    else
    {
        // Roll back to the long-lived interface
        TI("Sysfs interface missing, using legacy /proc");
        int current = nd_get_current_hugepages_legacy();
        TI("current: %d", current);
        ret = nd_set_hugepages_legacy((current + delta_pages));
        int tmp = nd_get_current_hugepages_legacy();

        TI("%s", ret ? "failed" : "succeed");
        TI("tmp: %d; (current + delta_pages): %d", tmp, (current + delta_pages));

        if (tmp > ((current + delta_pages)))
        {
            TI("After setting the number of hugepages is greater than expected");
            RInt(0);
        }
        else if ((tmp < ((current + delta_pages))) && (tmp > 0) && (tmp > current))
        {
            TI("After setting, the number of hugepages has increased by a part on the original basis");
            RInt(0);
        }
        else if ((tmp < ((current + delta_pages))) && (tmp > 0) && (tmp < current))
        {
            TI("After setting, the number of hugepages is smaller than the original");
            RInt(0);
        }
        else if ((tmp < 0))
        {
            TI("After setting, the number of hugepages becomes negative");
            RInt(-1);
        }
        else if (tmp == ((current + delta_pages)))
        {
            TI("When set, the number of hugepages is consistent with the expected value");
            RInt(0);
        }
        else
        {
            TI("I don't know");
            RInt(-1);
        }
    }

    RInt(ret);
}


/**
 * @brief
 *  Check if the directory exists
 * @param path
 *  The path that needs to be detected
 * @return
 *  1 is returned for success
 *  0 is returned for failure
 */
int nd_dir_exists(const char *path)
{
    TC("Called { %s(%s)", __func__, path);
    struct stat st;
    RInt(stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}


/**
 * @brief
 *  Create a directory (recursively, similar to mkdir -p)
 * @param path
 *  A directory that needs to be created
 * @return
 *  Returns 0 for success
 *  Returns -1 for failure
 */
int nd_mkdir_p(const char *path)
{

    TC("Called { %s(%s)", __func__, path);

    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);

    // Remove the end slash
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            {
                TE("[errno: %d]Failed to create directory %s: %s", errno, tmp, strerror(errno));
                RInt(-1);
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
    {
        TE("[errno: %d]Failed to create directory %s: %s", errno, tmp, strerror(errno));
        RInt(-1);
    }

    RInt(0);
}


/**
 * @brief
 *  Check if hugetlbfs is mounted to the target path
 * @return
 *  Function execution failure returns -1
 *  Returns 0 if not mounted
 *  Mount returns 1
 */
int nd_is_hugetlbfs_mounted(void)
{

    TC("Called { %s(void)", __func__);

    FILE *fp = fopen(ND_SYS_PROC_MOUNT_INFO, "r");
    if (!fp)
    {
        TE("[errno: %d]Failed to open %s; errmsg: %s", errno, ND_SYS_PROC_MOUNT_INFO, strerror(errno));
        RInt(-1);
    }

    char line[512];
    int mounted = 0;
    while (fgets(line, sizeof(line), fp) != NULL)
    {

        char fstype[128], mountpoint[128];

        if (sscanf(line, "%*s %127s %127s %*s %*s", mountpoint, fstype) == 2)
        {
            if ((strcmp(fstype, "hugetlbfs") == 0))
            {
                mounted = 1;
                strncpy(nd_G_store_mountpoint, mountpoint, nd_G_store_mountpoint_space);
                break;
            }
        }
    }

    fclose(fp);

    RInt(mounted);
}


/**
 * @brief
 *  Mounting Hugetlbfs (Requires Root Privilege)
 * @return
 *  Returns 0 for success
 *  Returns -1 for failure
 */
int nd_mount_hugetlbfs(void)
{

    TC("Called { %s(void)", __func__);

    // 1. Check whether it is mounted
    int mounted = nd_is_hugetlbfs_mounted();

    if (mounted == 1)
    {
        RInt(0); // Mounted
    }

    if (mounted == -1) {
        RInt(-1); // The check failed
    }

    // 2. Create a mount directory
    if (!nd_dir_exists(ND_HUGETLB_MOUNT_POINT))
    {
        if (nd_mkdir_p(ND_HUGETLB_MOUNT_POINT) != 0)
        {
            RInt(-1);
        }
    }

    // 3. Perform a mount (using the mount system call)
    if (mount("none", ND_HUGETLB_MOUNT_POINT, "hugetlbfs", MS_NOATIME | MS_NOSUID | MS_NODEV, "pagesize=2M") != 0)
    {
        TE("[errno: %d]Failed to mount hugetlbfs: %s", errno, strerror(errno));
        RInt(-1);
    }

    strncpy(nd_G_store_mountpoint, ND_HUGETLB_MOUNT_POINT, nd_G_store_mountpoint_space);

    RInt(0);
}


/**
 * @brief
 *  Read the /proc/meminfo file to verify that the large page memory is set
 * @param Rtotal
 *  The total number of hugepages is stored.
 * @param Rfree
 *  Stores the total number of HugePage idle.
 * @return
 *  Returns 0 for success
 *  Returns -1 for failure
 */
int nd_validate_hugepage_distribution(int *Rtotal, int *Rfree)
{
    TC("Called { %s(%p, %p)", __func__, Rtotal, Rfree);

    int ret = -1;

    FILE *fp = fopen(ND_SYS_PROC_MEMORY_INFO, "r");
    if (!fp)
    {
        TE("[errno: %d]Failed to open %s; errmsg: %s", errno, ND_SYS_PROC_MEMORY_INFO, strerror(errno));
        RInt(-1);
    }

    *Rtotal = -1, *Rfree = -1;

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL)
    {

        char title[128] = {0}, value[128] = {0};

        if (sscanf(line, "%127s %127s %*s", title, value) == 2)
        {
            if ((strcmp(title, "HugePages_Total:") == 0))
            {
                TI("title: %s; value: %s", title, value);
                *Rtotal = atoi(value);
            }
            if ((strcmp(title, "HugePages_Free:") == 0))
            {
                TI("title: %s; value: %s", title, value);
                *Rfree = atoi(value);
            }

            if ((*Rfree != -1) && (*Rfree != -1))
            {
                break;
            }
        }
    }

    if ((*Rtotal == -1) || (*Rfree == -1))
        ret = -1;
    else
        ret = 0;

    RInt(ret);
}


/**
 * @brief
 *  Sets large page memory globally
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int nd_Global_set_hugepage_memory(void)
{

    TC("Called { %s(void)", __func__);



    RInt(ND_OK);
}


/**
 * @brief
 *  Global fallback settings for large page memory
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int nd_fallback_hugepage_setting (void)
{

    TC("Called { %s(void)", __func__);


    RInt(ND_OK);
}


#if 0


/**
 * @note
 * 
 * Currently, the hugepage code is not used.
 * 
 * Use when debugging performance.
 * 
 * This commented out code still needs to be polished
 * 
 * The corresponding original file name is hugepage.c
 * 
 * The original question and answer file name is sethugepages.txt
 * 
 * The above two files are stored in the upper directory netdump-back
 * 
 */

 
/**
 * @brief
 *  The mmap function maps large page memory
 */
static void * nd_mmap_hp_mem(void) 
{

    char name[256] = {0};
    sprintf(name, "%s/%s", nd_G_store_mountpoint, "ndhp");
    fprintf(stderr, "[%d] name: %s\n", __LINE__, name);

    int fd = open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) 
    {
        fprintf(stderr, "[%d][errno: %d]errmsg: %s\n", __LINE__, errno, strerror(errno));
        return NULL;
    }

    int ret = ftruncate(fd, (1<<23));
    if (ret < 0) {
        fprintf(stderr, "[%d][errno: %d]errmsg: %s\n", __LINE__, errno, strerror(errno));
        close(fd);
        return NULL;
    }
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
    void * mem = mmap(NULL, (1<<23), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_HUGETLB, fd, 0);
    if (MAP_FAILED == mem) {
        fprintf(stderr, "[%d][errno: %d]errmsg: %s\n", __LINE__, errno, strerror(errno));
        close(fd);
        unlink(name);
        return NULL;
    }

    close(fd);

    return mem;
}


/**
 * @brief
 */
static int nd_munmap_hp_mem(void * mem) 
{

    munmap(mem, (1<<23));

    char name[256] = {0};
    sprintf(name, "%s/%s", nd_G_store_mountpoint, "ndhp");

    fprintf(stderr, "[%d] name: %s\n", __LINE__, name);

    unlink(name);

    return 0;
}



int main () 
{

    int ret = -1;

    ret = nd_mount_hugetlbfs();
    fprintf(stderr, "[%d] nd_mount_hugetlbfs return: %d\n", __LINE__, ret);
    getchar();


    ret = -1;
    ret = nd_disable_transparent_hugepages();
    fprintf(stderr, "[%d] nd_disable_transparent_hugepages return: %d\n", __LINE__, ret);
    getchar();


    ret = -1;
    ret = nd_set_hugepages_incremental(2048, HUGEPAGE_2MB);
    fprintf(stderr, "[%d] nd_set_hugepages_incremental return: %d\n", __LINE__, ret);
    getchar();


    ret = -1;
    ret = nd_mount_hugetlbfs();
    fprintf(stderr, "[%d] nd_mount_hugetlbfs return: %d\n", __LINE__, ret);
    getchar();


    ret = -1;
    int Rtotal = 0, Rfree = 0;
    ret = nd_validate_hugepage_distribution (&Rtotal, &Rfree);
    fprintf(stderr, "[%d] nd_validate_hugepage_distribution return %d\n", __LINE__, ret);
    fprintf(stderr, "[%d] total: %d; free: %d\n", __LINE__, Rtotal, Rfree);
    getchar();


    // mmap
    void * mem = nd_mmap_hp_mem();
    if (!mem) {
        fprintf(stderr, "[%d] nd_mmap_hp_mem return %p", __LINE__, mem);
    }
    else {
        fprintf(stderr, "[%d] nd_mmap_hp_mem return %p", __LINE__, mem);
    }
    getchar();

    // munmap
    nd_munmap_hp_mem(mem);
    getchar();



    ret = -1;
    ret = nd_set_hugepages_incremental((-2048), HUGEPAGE_2MB);
    fprintf(stderr, "[%d] nd_set_hugepages_incremental return: %d\n", __LINE__, ret);
    getchar();


    ret = -1;
    Rtotal = 0, Rfree = 0;
    ret = nd_validate_hugepage_distribution (&Rtotal, &Rfree);
    fprintf(stderr, "[%d] nd_validate_hugepage_distribution return %d\n", __LINE__, ret);
    fprintf(stderr, "[%d] total: %d; free: %d\n", __LINE__, Rtotal, Rfree);
    getchar();


    ret = -1;
    ret = nd_recover_transparent_hugepages();
    fprintf(stderr, "[%d] nd_recover_transparent_hugepages return: %d\n", __LINE__, ret);
    getchar();

    return 0;
}

#endif
#endif

/** =========================================================================================== */


/**
 * @brief
 *  Call the mmap function to open up memory space
 * @param name
 *  The name of the file
 * @param baseaddr
 *  Starting base address
 * @param memspace
 *  The size of each memory block
 * @param count
 *  Number of memory blocks
 * @return 
 *  Returns the address of the allocated space if successful, 
 *  otherwise returns NULL
 */
void * nd_called_open_mmap_openup_memory (
    const char * name, void * baseaddr, unsigned long long memspace, unsigned int count) {

    TC("Called { %s(%s, %p, %llu, %u)", __func__, name, (void *)baseaddr, memspace, count);

    if (unlikely((!(POWEROF2(count))))) {
		TE("POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

    int fd = -1;
	if (unlikely((fd = open(name, O_RDWR |O_CREAT, 0666)) < 0)) {
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    if(unlikely(ftruncate(fd, (count * memspace)) == -1)){
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address((uintptr_t)baseaddr)));

    void *p = mmap((void *)(align_address((uintptr_t)baseaddr)), (count * memspace),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED /*| MAP_POPULATE | MAP_HUGETLB */, fd, 0);

    if(unlikely((p == MAP_FAILED))) {
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	if (unlikely((!p))) {
        close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr((p));
}


/**
 * @brief
 *  Call the mmap function to open up memory space
 * @param name
 *  The name of the file
 * @param baseaddr
 *  Starting base address
 * @param memspace
 *  The size of memory 
 * @return
 *  Returns the address of the allocated space if successful,
 *  otherwise returns NULL
 */
void *nd_called_shmopen_mmap_openup_memory (const char *name, void *baseaddr, unsigned int memsize)
{

    TC("Called { %s(%s, %p, %u)", __func__, name, (void *)baseaddr, memsize);

    int fd = -1;
    if (unlikely((fd = shm_open(name, O_RDWR | O_CREAT, 0666)) < 0))
    {
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    if (unlikely(ftruncate(fd, memsize) == -1))
    {
        close(fd);
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address((uintptr_t)baseaddr)));

    void *p = mmap((void *)(align_address((uintptr_t)baseaddr)), memsize,
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED /* | MAP_POPULATE | MAP_HUGETLB */, fd, 0);

    if (unlikely((p == MAP_FAILED)))
    {
        close(fd);
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    if (unlikely((!p)))
    {
        close(fd);
        TE("%s", strerror(errno));
        RVoidPtr(NULL);
    }

    close(fd);

    RVoidPtr((p));
}


/**
 * @brief
 *  Call the mmap function to look up memory space
 * @param name
 *  The name of the file
 * @param baseaddr
 *  Starting base address
 * @param memspace
 *  The size of each memory block
 * @param count
 *  Number of memory blocks
 * @return 
 *  Returns the address of the allocated space if successful, 
 *  otherwise returns NULL
 */
void * nd_called_mmap_lookup_memory (
    const char * name, void * baseaddr, unsigned int memspace, unsigned int count) {

    TC("Called { %s(%s, %p, %u, %u)", __func__, name, baseaddr, memspace, count);

    if (unlikely((!(POWEROF2(count))))) {
		TE("POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

	int fd = -1;
    if (unlikely((fd = open(name, O_RDWR, 0666)) == -1)) {
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address((uintptr_t)baseaddr)));

    void *p = mmap((void *)(align_address((uintptr_t)baseaddr)), (count * memspace),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

    if(unlikely((p == MAP_FAILED) || (p == NULL))){
        close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr((p));
}


/**
 * @brief
 *  Use the select function to achieve millisecond delay
 * @param sec
 *  Delay in second
 * @param nanoseconds
 *  Delay in nanoseconds
 */
void nd_delay_microsecond(unsigned int sec, unsigned long nanoseconds)
{
    //TC("Called { %s(%u, %lu)", __func__, sec, microseconds);

    #if 0
    struct timeval timeout = {sec, microseconds};
    
    if (unlikely(((select(0, NULL, NULL, NULL, &timeout)) == -1))) {
        TE("%s", strerror(errno));
    }
    #endif

    struct timespec req = {
        .tv_sec = sec,
        .tv_nsec = nanoseconds
    };

    nanosleep(&req, NULL);

    //RVoid();
}


/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
/**
 * @brief
 *  Copy src to string dst of size siz.
 * @param dst
 *  dst addr
 * @param src
 *  src addr
 * @param siz
 *  length
 * @return 
 *  copy length
 */
size_t strlcpy(char *dst, const char *src, size_t siz)
{
    //TC("Called { %s(%p, %p, %ld)", __func__, dst, src, siz);

    char *d = dst;
    const char *s = src;
    size_t n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0)
    {
        do
        {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0)
    {
        if (siz != 0)
            *d = '\0'; /* NUL-terminate dst */
        while (*s++)
            ;
    }

    return (s - src - 1); /* count does not include NUL */
    //RULong((s - src - 1));
}


/**
 * @brief
 *  Take the node from the head of the doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t * nd_dll_takeout_from_head(nd_dll_t ** head, nd_dll_t ** tail)
{

    //TC("Called { %s(%p, %p)", __func__, head, tail);

    nd_dll_t * tmp = NULL;

    if (!head || !tail) {
        TE("Param is null; head: %p, tail: %p;", head, tail);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    if (!(*head) && !(*tail)) {
        TE("Param is null; *head: %p; *tail: %p", *head, *tail);
        //RVoidPtr(tmp);
        return tmp;
    }

    tmp = *head;

    *head = tmp->next;
    if (*head) 
        (*head)->prev = NULL;
    else
        *tail = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    //RVoidPtr(tmp);
    return tmp;
}


/**
 * @brief
 *  Take the node from the head of the doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t *nd_dll_takeout_from_head_s(nd_dll_t ** head)
{

    //TC("Called { %s(%p)", __func__, head);

    nd_dll_t *tmp = NULL;

    if (!head) {
        TE("Param is null; head: %p", head);
        exit(1);
    }

    if (!(*head)) {
        TE("Param is null; *head: %p", *head);
        //RVoidPtr(tmp);
        return tmp;
    }

    tmp = *head;

    *head = tmp->next;
    if (*head)
        (*head)->prev = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    //RVoidPtr(tmp);
    return tmp;
}


/**
 * @brief
 *  Take the node from the tail of the doubly linked list
 * @memberof tail
 *  the tail of the doubly linked list
 * @return
 *  Returns the retrieved node if successful, otherwise returns NULL
 */
nd_dll_t * nd_dll_takeout_from_tail(nd_dll_t ** head, nd_dll_t ** tail)
{

    //TC("Called { %s(%p, %p)", __func__, head, tail);

    nd_dll_t * tmp = NULL;

    if (!head || !tail) {
        TE("Param is null; head: %p, tail: %p", head, tail);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    if (!(*tail) && !(*head)) {
        TE("Param is numm; *tail: %p", *tail);
        //RVoidPtr(tmp);
        return tmp;
    }

    tmp = *tail;

    *tail = tmp->prev;
    if (*tail)
        (*tail)->next = NULL;
    else 
        *head = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    //RVoidPtr(tmp);
    return tmp;
}


/**
 * @brief
 *  Insert the head of a doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_intsert_into_head (nd_dll_t ** head, nd_dll_t ** tail, nd_dll_t * node)
{

    //TC("Called { %s(%p, %p, %p)", __func__, head, tail, node);

    if (!head || !tail || !node) {
        TE("Param is null; head: %p; node: %p", head, node);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    nd_dll_t * tmp = *head;

    if (!(*head)) {
        node->next = NULL;
        *tail = node;
    }
    else {
        node->next = tmp;
    }

    node->prev = NULL;

    if (tmp)
        tmp->prev = node;

    *head = node;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief
 *  Insert the head of a doubly linked list
 * @memberof head
 *  the head of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_intsert_into_head_s(nd_dll_t ** head, nd_dll_t * node)
{

    //TC("Called { %s(%p, %p)", __func__, head, node);

    if (!head || !node)
    {
        TE("Param is null; head: %p; node: %p", head, node);
        exit(1);
    }

    nd_dll_t *tmp = *head;

    if (!(*head))
        node->next = NULL;
    else
        node->next = tmp;

    node->prev = NULL;

    if (tmp)
        tmp->prev = node;

    *head = node;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief
 *  insert the head of a doubly linked list (multiple)
 * @param head
 *  the head of the doubly linked list
 * @param nodehead
 *  list head to be inserted
 * @param nodetail
 *  list tail to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_insert_into_head_multiple (nd_dll_t ** head, nd_dll_t * nodehead, nd_dll_t * nodetail)
{

    //TC("Called { %s(%p, %p, %p)", __func__, head, nodehead, nodetail);

    if (!head || !nodehead || !nodetail) 
    {
        TE("there is a case where the parameter is NULL(head: %p, nodehead: %p, nodetail: %p)",
           head, nodehead, nodetail);
        exit(1);
    }

    nd_dll_t * tmp = *head;

    if (!(*head))
        nodetail->next = NULL;
    else
        nodetail->next = tmp;

    nodehead->prev = NULL;

    if (tmp)
        tmp->prev = nodetail;

    *head = nodehead;

    //RInt(ND_OK);
    return ND_OK;
}


/**
 * @brief
 *  Insert the tail of a doubly linked list
 * @memberof tail
 *  the tail of the doubly linked list
 * @memberof node
 *  node to be inserted
 * @return
 *  If successful, it returns ND_OK
 *  if failed, it returns ND_ERR
 */
int nd_dll_insert_into_tail(nd_dll_t ** head, nd_dll_t ** tail, nd_dll_t * node)
{
    //TC("Called { %s(%p, %p, %p)", __func__, head, tail, node);

    if (!head || !tail || !node) {
        TE("Param is null; head: %p, tail: %p; node: %p", head, tail, node);
        exit(1);
    }

    if ((!(*head) && (*tail)) || ((*head) && !(*tail))) {
        TE("fatal logic error; *head: %p; *tail: %p", *head, *tail);
        exit(1);
    }

    nd_dll_t * tmp = *tail;

    if (!(*tail)) {
        node->prev = NULL;
        *head = node;
    }
    else {
        node->prev = tmp;
    }

    node->next = NULL;

    if (tmp)
        tmp->next = node;

    *tail = node;

    //RInt(ND_OK);
    return ND_OK;
}