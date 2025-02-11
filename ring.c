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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <inttypes.h>
#include <errno.h>

#include "ring.h"
#include "common.h"
#include "trace.h"


/**
 * @brief 
 * 	true if x is a power of 2
 */
#ifndef POWEROF2
#define POWEROF2(x) ((((x)-1) & (x)) == 0)
#endif /* POWEROF2 */


/**
 * Change the high water mark.
 *
 * If *count* is 0, water marking is disabled. Otherwise, it is set to the
 * *count* value. The *count* value must be greater than 0 and less
 * than the ring size.
 *
 * This function can be called at any time (not necessarily at
 * initialization).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param count
 *   The new water mark value.
 * @return
 *   - 0: Success; water mark changed.
 *   - -EINVAL: Invalid water mark value.
 */
int ring_set_water_mark(ring_t *r, unsigned count)
{

	TC("Called { %s(%p, %u)", __func__, r, count);

	if (unlikely(count >= r->prod.size)) {
		TE("count(%u) >= r->prod.size(%u)", count, r->prod.size);
		RInt(-EINVAL);
	}

	/* if count is 0, disable the watermarking */
	if (count == 0)
		count = r->prod.size;

	r->prod.watermark = count;

	RInt(0);
}


/**
 * Dump the status of the ring to the console.
 *
 * @param r
 *   A pointer to the ring structure.
 */
void ring_dump(const ring_t *r)
{

	TC("Called { %s(%p)", __func__, r);

	if (unlikely((!r))) return;

	//TI("ring <%s>@%p\n", r->name, r);
	TI("  flags=%x\n", r->flags);
	TI("  size=%"PRIu32"\n", r->prod.size);
	TI("  ct=%"PRIu32"\n", r->cons.tail);
	TI("  ch=%"PRIu32"\n", r->cons.head);
	TI("  pt=%"PRIu32"\n", r->prod.tail);
	TI("  ph=%"PRIu32"\n", r->prod.head);
	TI("  used=%u\n", ring_count(r));
	TI("  avail=%u\n", ring_free_count(r));
	if (r->prod.watermark == r->prod.size) {
		TI("  watermark=0\n");
	}
	else {
		TI("  watermark=%"PRIu32"\n", r->prod.watermark);
	}
	TI("  no statistics available\n");

	RVoid();
}


/**
 * Create a new ring named *name* in memory.
 *
 * This function uses ``memzone_reserve()`` to allocate memory. Its size is
 * set to *count*, which must be a power of two. Water marking is
 * disabled by default.
 * Note that the real usable ring size is *count-1* instead of
 * *count*.
 *
 * @param name
 *   The name of the ring.
 * @param baseaddr 
 *   Starting base address
 * @param count 
 *   The size of the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``ring_enqueue()`` or ``ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``ring_dequeue()`` or ``ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   On success, the pointer to the new allocated ring. NULL on error with
 *    ue_errno set appropriately. Possible errno values include:
 *    - E_UE_NO_CONFIG - function could not get pointer to ue_config structure
 *    - E_UE_SECONDARY - function was called from a secondary process instance
 *    - E_UE_NO_TAILQ - no tailq list could be got for the ring list
 *    - EINVAL - count provided is not a power of 2
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
ring_t * ring_create(const char * name, uintptr_t baseaddr, int count, int flags)
{

	TC("Called { %s(%s, %p, %d, %d)", __func__, name, (void *)baseaddr, count, flags);

	if (unlikely((!(POWEROF2(count))))) {
		TE("POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

	int fd = -1;
	if (unlikely(fd = open(name, O_RDWR |O_CREAT, 0666)) < 0) {
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}


	if(unlikely(ftruncate(fd, (count * (sizeof(void *)) + sizeof(ring_t))) == -1)){
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	TI("align_address(%p) : %p", (void *)baseaddr, (void *)(align_address(baseaddr)));

	ring_t * ring = (ring_t*)mmap(
				(void *)(align_address(baseaddr)), 
				(count * (sizeof(void *)) + sizeof(ring_t)), 
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, 
				fd , 0
			);

	if(unlikely(ring == MAP_FAILED)) {
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	if (unlikely(!ring)) {
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	/* init the ring structure */
	memset(ring, 0, sizeof(*ring));
	//snprintf(ring->name, sizeof(ring->name), "%s", name);
	ring->flags = flags;
	//ring->count = count;
	ring->prod.watermark = count;
	ring->prod.sp_enqueue = !!(flags & RING_F_SP_ENQ);
	ring->cons.sc_dequeue = !!(flags & RING_F_SC_DEQ);
	ring->prod.size = ring->cons.size = count;
	ring->prod.mask = ring->cons.mask = count - 1;
	ring->prod.head = ring->cons.head = 0;
	ring->prod.tail = ring->cons.tail = 0;
	
	RVoidPtr(ring);
}


/**
 * @brief
 * 	Init memory
 * @param addr
 *   Starting address
 * @param count
 *   The size of the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``ring_enqueue()`` or ``ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``ring_dequeue()`` or ``ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 */
void *ring_init(void *addr, int count, int flags) 
{
	TC("Called {%s(%p, %d, %d)", __func__, addr, count, flags);

	ring_t * ring = (ring_t *)(addr);

	memset(ring, 0, sizeof(*ring));

	ring->flags = flags;
	ring->prod.watermark = count;
	ring->prod.sp_enqueue = !!(flags & RING_F_SP_ENQ);
	ring->cons.sc_dequeue = !!(flags & RING_F_SC_DEQ);
	ring->prod.size = ring->cons.size = count;
	ring->prod.mask = ring->cons.mask = count - 1;
	ring->prod.head = ring->cons.head = 0;
	ring->prod.tail = ring->cons.tail = 0;

	RVoidPtr((void *)ring);
}

/**
 * Search a ring from its name
 *
 * @param name
 *   The name of the ring.
 * @param baseaddr 
 * 	 Starting base address
 * @param count 
 * 	 The size of the ring (must be a power of 2).
 * @return
 *   The pointer to the ring matching the name, or NULL if not found,
 *   with ue_errno set appropriately. Possible ue_errno values include:
 *    - ENOENT - required entry not available to return.
 */
ring_t * ring_lookup(const char *name, uintptr_t baseaddr, int count)
{
    
	TC("Called { %s(%s, %p, %d)", __func__, name, (void *)baseaddr, count);

	if (unlikely((!(POWEROF2(count))))) {
		TE("POWEROF2(%d) is False", count);
		RVoidPtr(NULL);
	}

	int fd = -1;
    if (unlikely((fd = open(name, O_RDWR, 0666)) == -1)) {
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

	TI("align_address(%p) : %p", (void *)(baseaddr), (void *)(align_address(baseaddr)));

    ring_t * ring = (ring_t*)mmap(
				(void *)(align_address(baseaddr)), 
				(count * (sizeof(void *)) + sizeof(ring_t)), 
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, 
				fd , 0
			);

    if(unlikely((ring == MAP_FAILED) || (ring == NULL))){
		close(fd);
		TE("%s", strerror(errno));
		RVoidPtr(NULL);
	}

    close(fd);

    RVoidPtr(ring);
}


/**
 * @brief 
 * 	Destroy the ring queue
 * @param ring 
 * 	The address of the ring queue
 */
void ring_free(ring_t *ring) {

	TC("Called { %s(%p)", __func__, ring);

	if (unlikely((!ring))) {
		TE("ring: %p", ring);
		RVoid();
	}

    munmap(ring, (ring->prod.size * (sizeof(void *)) + sizeof(ring_t)));

	RVoid();
}
