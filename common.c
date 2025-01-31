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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
            T("errmsg: %s", strerror(errno));
            RInt(ND_ERR);
        }
        T("infomsg: directory created: %s", fpath);
    } else if (S_ISDIR(statbuf.st_mode)) {
        T("infomsg: directory exists: %s", fpath);
    } else {
        T("infomsg: Path exists but is not a directory: %s", fpath);
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
            T("infomsg: File deleted: %s", fname);
        } else {
            T("errmsg: %s", strerror(errno));
            RInt(ND_ERR);
        }
    } else {
        T("infomsg: File does not exist: %s", fname);
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
        T("errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    T("infomsg: directory is writable %s", fpath);

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
        T("errmsg: %s", strerror(errno));
        RInt(ND_ERR);
    }

    T("infomsg: directory is readable: %s\n", fpath);

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