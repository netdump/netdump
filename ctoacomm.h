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

#ifndef __CTOACOMM_H__
#define __CTOACOMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap.h"
#include "common.h"
#include "ring.h"

/**
 * @brief
 *  Capture the parsed packet header
 */
typedef struct {

    long dlt;
    struct pcap_pkthdr pphdr;
    char data[0];

} ctoa_t;


#endif  // __CTOACOMM_H__