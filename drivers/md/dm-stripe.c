/*
 * Copyright (C) 2001-2003 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include <linux/device-mapper.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/dax.h>
#include <linux/slab.h>
#include <linux/log2.h>

#define DM_MSG_PREFIX "striped"
#define DM_IO_ERROR_THRESHOLD 15

/*
 条带映射target类型对应target device的结构
 描述mapped_device 到它某个 target device 的映射关系
 以便 IO 请求映射时的查找操作
*/
struct stripe {
	struct dm_dev *dev;//对应物理设备的dm_dev结构指针
	sector_t physical_start;//物理设备中以扇区为单位的起始位置
	atomic_t error_count;
};
//typedef的结构
struct stripe_c {
	uint32_t stripes;
	//条带序号
	int stripes_shift;
	/* 条带对应的扇区大小*/
	sector_t stripe_width;
	//块大小
	uint32_t chunk_size;
	int chunk_size_shift;
	/* 需要处理的事件 */
	struct dm_target *ti;
	/* 用于触发事件的工作结构*/
	struct work_struct trigger_event;
	//以映射结构为单元的条带数组
	struct stripe stripe[0];
};

/*
 * An event is triggered whenever a drive
 * drops out of a stripe volume.
 */
static void trigger_event(struct work_struct *work)
{
	struct stripe_c *sc = container_of(work, struct stripe_c,
					   trigger_event);
	dm_table_event(sc->ti->table);
}

static inline struct stripe_c *alloc_context(unsigned int stripes)
{
	size_t len;

	if (dm_array_too_big(sizeof(struct stripe_c), sizeof(struct stripe),
			     stripes))
		return NULL;

	len = sizeof(struct stripe_c) + (sizeof(struct stripe) * stripes);

	return kmalloc(len, GFP_KERNEL);
}

/*
 * Parse a single <dev> <sector> pair
 */
static int get_stripe(struct dm_target *ti, struct stripe_c *sc,
		      unsigned int stripe, char **argv)
{
	unsigned long long start;
	char dummy;
	int ret;

	if (sscanf(argv[1], "%llu%c", &start, &dummy) != 1)
		return -EINVAL;

	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
			    &sc->stripe[stripe].dev);
	if (ret)
		return ret;

	sc->stripe[stripe].physical_start = start;

	return 0;
}

/*
 * Construct a striped mapping.
 * <number of stripes> <chunk size> [<dev_path> <offset>]+
 */
static int stripe_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct stripe_c *sc;
	sector_t width, tmp_len;
	uint32_t stripes;
	uint32_t chunk_size;
	int r;
	unsigned int i;

	if (argc < 2) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}

	if (kstrtouint(argv[0], 10, &stripes) || !stripes) {
		ti->error = "Invalid stripe count";
		return -EINVAL;
	}

	if (kstrtouint(argv[1], 10, &chunk_size) || !chunk_size) {
		ti->error = "Invalid chunk_size";
		return -EINVAL;
	}

	width = ti->len;
	if (sector_div(width, stripes)) {
		ti->error = "Target length not divisible by "
		    "number of stripes";
		return -EINVAL;
	}

	tmp_len = width;
	if (sector_div(tmp_len, chunk_size)) {
		ti->error = "Target length not divisible by "
		    "chunk size";
		return -EINVAL;
	}

	/*
	 * Do we have enough arguments for that many stripes ?
	 */
	if (argc != (2 + 2 * stripes)) {
		ti->error = "Not enough destinations "
			"specified";
		return -EINVAL;
	}

	sc = alloc_context(stripes);
	if (!sc) {
		ti->error = "Memory allocation for striped context "
		    "failed";
		return -ENOMEM;
	}

	INIT_WORK(&sc->trigger_event, trigger_event);

	/* Set pointer to dm target; used in trigger_event */
	sc->ti = ti;
	sc->stripes = stripes;
	sc->stripe_width = width;

	if (stripes & (stripes - 1))
		sc->stripes_shift = -1;
	else
		sc->stripes_shift = __ffs(stripes);

	r = dm_set_target_max_io_len(ti, chunk_size);
	if (r) {
		kfree(sc);
		return r;
	}

	ti->num_flush_bios = stripes;
	ti->num_discard_bios = stripes;
	ti->num_secure_erase_bios = stripes;
	ti->num_write_same_bios = stripes;
	ti->num_write_zeroes_bios = stripes;

	sc->chunk_size = chunk_size;
	if (chunk_size & (chunk_size - 1))
		sc->chunk_size_shift = -1;
	else
		sc->chunk_size_shift = __ffs(chunk_size);

	/*
	 * Get the stripe destinations.
	 */
	for (i = 0; i < stripes; i++) {
		argv += 2;

		r = get_stripe(ti, sc, i, argv);
		if (r < 0) {
			ti->error = "Couldn't parse stripe destination";
			while (i--)
				dm_put_device(ti, sc->stripe[i].dev);
			kfree(sc);
			return r;
		}
		atomic_set(&(sc->stripe[i].error_count), 0);
	}

	ti->private = sc;

	return 0;
}
static void stripe_dtr(struct dm_target *ti)
{
	unsigned int i;
	struct stripe_c *sc = (struct stripe_c *) ti->private;

	for (i = 0; i < sc->stripes; i++)
		dm_put_device(ti, sc->stripe[i].dev);

	flush_work(&sc->trigger_event);
	kfree(sc);
}
//计算条带序号，计算bio对应的物理设备中的块序号
static void stripe_map_sector(struct stripe_c *sc, sector_t sector,
			      uint32_t *stripe, sector_t *result){
	//块对应的扇区为待处理事件对应的偏移量（扇区为单位）
	sector_t chunk = dm_target_offset(sc->ti, sector);
	sector_t chunk_offset;
	//如果条带的块大小的变化<0
	if (sc->chunk_size_shift < 0)
		//块偏移为待扇区对应的块大小
		chunk_offset = sector_div(chunk, sc->chunk_size);
	else {
		//否则，有变化，块偏移量为chunk数量&对应的块大小-1
		chunk_offset = chunk & (sc->chunk_size - 1);
		//chunk号右移为对应块号的变化量
		chunk >>= sc->chunk_size_shift;
	}
	//如果条带的变化<0	
	if (sc->stripes_shift < 0)
		//条带号为扇区设备中条带序号
		*stripe = sector_div(chunk, sc->stripes);
	else {
		//否则条带号为块序号模去（条带数量-1）
		*stripe = chunk & (sc->stripes - 1);
		//块号右移为条带的偏移量
		chunk >>= sc->stripes_shift;
	}
	//计算完条带后，再次检查块大小变化
	if (sc->chunk_size_shift < 0)
		chunk *= sc->chunk_size;
	else
		chunk <<= sc->chunk_size_shift;
	*result = chunk + chunk_offset;	//结果为块号+块位移
}
//条带映射到扇区的范围
static void stripe_map_range_sector(struct stripe_c *sc, sector_t sector,
				    uint32_t target_stripe, sector_t *result)
{
	uint32_t stripe;
	//计算条带对应的块号
	stripe_map_sector(sc, sector, &stripe, result);
	if (stripe == target_stripe)
		return;
	/* round down */
	sector = *result;
	if (sc->chunk_size_shift < 0)
		//结果为条带中块数量
		*result -= sector_div(sector, sc->chunk_size);
	else
		*result = sector & ~(sector_t)(sc->chunk_size - 1);
	//如果目标条带比当前对应的条带序号小，则结果+一条条带对应块数
	if (target_stripe < stripe)
		*result += sc->chunk_size;		/* next chunk */
}

//条带映射的范围计算，bio迭代器大小计算
static int stripe_map_range(struct stripe_c *sc, struct bio *bio,
			    uint32_t target_stripe)
{
	sector_t begin, end;
	//赋值bio请求对应的迭代器的扇区号映射到物理设备上对应的扇区号
	stripe_map_range_sector(sc, bio->bi_iter.bi_sector,
				target_stripe, &begin);
	//赋值bio请求对应的结束扇区号映射到物理设备上对应的扇区号
	stripe_map_range_sector(sc, bio_end_sector(bio),
				target_stripe, &end);
	//如果起始扇区号小于结束扇区号
	if (begin < end) {
		//修改设备号为当前物理设备的设备号
		bio_set_dev(bio, sc->stripe[target_stripe].dev->bdev);
		//bio迭代器起始扇区号为对应起始扇区号+条带的物理起始位置
		bio->bi_iter.bi_sector = begin +
			sc->stripe[target_stripe].physical_start;
		//修改迭代器的bi大小
		bio->bi_iter.bi_size = to_bytes(end - begin);
		return DM_MAPIO_REMAPPED;
	} else {
		//当前映射范围不匹配目标设备的条带
		/* The range doesn't map to the target stripe */
		bio_endio(bio);
		//返回告诉DM不要再处理了
		return DM_MAPIO_SUBMITTED;
	}
}
//bio（块设备的io请求）映射到最终存储它的设备上的相应位置
static int stripe_map(struct dm_target *ti, struct bio *bio){
	struct stripe_c *sc = ti->private;
	uint32_t stripe;
	unsigned target_bio_nr;
	//bi_opf域上的标志查看,判断bio是否是REQ_PREFLUSH，进行特殊处理
	if (bio->bi_opf & REQ_PREFLUSH) {
		target_bio_nr = dm_bio_get_target_bio_nr(bio);
		BUG_ON(target_bio_nr >= sc->stripes);
		//修改bio请求对应的设备指针为对应的物理设备指针
		bio_set_dev(bio, sc->stripe[target_bio_nr].dev->bdev);
		//如果map函数修改了bio的内容，希望DM将bio按照新内容再分发，那么就返回DM_MAPIO_REMAPPED
		return DM_MAPIO_REMAPPED;
	}	
	if (unlikely(bio_op(bio) == REQ_OP_DISCARD) ||//告诉块设备放弃使用某指定的块
	    ////Secure Erase 仅会删除映象表而不会擦除所有已经被写入的块
	    unlikely(bio_op(bio) == REQ_OP_SECURE_ERASE) ||
	    //对指定的1个或者多个扇区写0 
	    unlikely(bio_op(bio) == REQ_OP_WRITE_ZEROES) ||
	    //将1个或者多个扇区写成相同的数据
	    unlikely(bio_op(bio) == REQ_OP_WRITE_SAME)) {
		//unlikely情况不经常发生
		target_bio_nr = dm_bio_get_target_bio_nr(bio);
		BUG_ON(target_bio_nr >= sc->stripes);
		//调用map_range函数
		return stripe_map_range(sc, bio, target_bio_nr);
	}
	stripe_map_sector(sc, bio->bi_iter.bi_sector,
			  &stripe, &bio->bi_iter.bi_sector);
	//直接修改bio的bi_sector和bi_bdev
	bio->bi_iter.bi_sector += sc->stripe[stripe].physical_start;
	bio_set_dev(bio, sc->stripe[stripe].dev->bdev);
	//如果map函数修改了bio的内容，希望DM将bio按照新内容再分发，那么就返回DM_MAPIO_REMAPPED
	return DM_MAPIO_REMAPPED;
}

#if IS_ENABLED(CONFIG_DAX_DRIVER)
static long stripe_dax_direct_access(struct dm_target *ti, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn)
{
	sector_t dev_sector, sector = pgoff * PAGE_SECTORS;
	struct stripe_c *sc = ti->private;
	struct dax_device *dax_dev;
	struct block_device *bdev;
	uint32_t stripe;
	long ret;

	stripe_map_sector(sc, sector, &stripe, &dev_sector);
	dev_sector += sc->stripe[stripe].physical_start;
	dax_dev = sc->stripe[stripe].dev->dax_dev;
	bdev = sc->stripe[stripe].dev->bdev;

	ret = bdev_dax_pgoff(bdev, dev_sector, nr_pages * PAGE_SIZE, &pgoff);
	if (ret)
		return ret;
	return dax_direct_access(dax_dev, pgoff, nr_pages, kaddr, pfn);
}

static size_t stripe_dax_copy_from_iter(struct dm_target *ti, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i)
{
	sector_t dev_sector, sector = pgoff * PAGE_SECTORS;
	struct stripe_c *sc = ti->private;
	struct dax_device *dax_dev;
	struct block_device *bdev;
	uint32_t stripe;

	stripe_map_sector(sc, sector, &stripe, &dev_sector);
	dev_sector += sc->stripe[stripe].physical_start;
	dax_dev = sc->stripe[stripe].dev->dax_dev;
	bdev = sc->stripe[stripe].dev->bdev;

	if (bdev_dax_pgoff(bdev, dev_sector, ALIGN(bytes, PAGE_SIZE), &pgoff))
		return 0;
	return dax_copy_from_iter(dax_dev, pgoff, addr, bytes, i);
}

static size_t stripe_dax_copy_to_iter(struct dm_target *ti, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i)
{
	sector_t dev_sector, sector = pgoff * PAGE_SECTORS;
	struct stripe_c *sc = ti->private;
	struct dax_device *dax_dev;
	struct block_device *bdev;
	uint32_t stripe;

	stripe_map_sector(sc, sector, &stripe, &dev_sector);
	dev_sector += sc->stripe[stripe].physical_start;
	dax_dev = sc->stripe[stripe].dev->dax_dev;
	bdev = sc->stripe[stripe].dev->bdev;

	if (bdev_dax_pgoff(bdev, dev_sector, ALIGN(bytes, PAGE_SIZE), &pgoff))
		return 0;
	return dax_copy_to_iter(dax_dev, pgoff, addr, bytes, i);
}

#else
#define stripe_dax_direct_access NULL
#define stripe_dax_copy_from_iter NULL
#define stripe_dax_copy_to_iter NULL
#endif

/*
 * Stripe status:
 *
 * INFO
 * #stripes [stripe_name <stripe_name>] [group word count]
 * [error count 'A|D' <error count 'A|D'>]
 *
 * TABLE
 * #stripes [stripe chunk size]
 * [stripe_name physical_start <stripe_name physical_start>]
 *
 */

static void stripe_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct stripe_c *sc = (struct stripe_c *) ti->private;
	unsigned int sz = 0;
	unsigned int i;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%d ", sc->stripes);
		for (i = 0; i < sc->stripes; i++)  {
			DMEMIT("%s ", sc->stripe[i].dev->name);
		}
		DMEMIT("1 ");
		for (i = 0; i < sc->stripes; i++) {
			DMEMIT("%c", atomic_read(&(sc->stripe[i].error_count)) ?
			       'D' : 'A');
		}
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%d %llu", sc->stripes,
			(unsigned long long)sc->chunk_size);
		for (i = 0; i < sc->stripes; i++)
			DMEMIT(" %s %llu", sc->stripe[i].dev->name,
			    (unsigned long long)sc->stripe[i].physical_start);
		break;
	}
}

static int stripe_end_io(struct dm_target *ti, struct bio *bio,
		blk_status_t *error)
{
	unsigned i;
	char major_minor[16];
	struct stripe_c *sc = ti->private;

	if (!*error)
		return DM_ENDIO_DONE; /* I/O complete */

	if (bio->bi_opf & REQ_RAHEAD)
		return DM_ENDIO_DONE;

	if (*error == BLK_STS_NOTSUPP)
		return DM_ENDIO_DONE;

	memset(major_minor, 0, sizeof(major_minor));
	sprintf(major_minor, "%d:%d", MAJOR(bio_dev(bio)), MINOR(bio_dev(bio)));

	/*
	 * Test to see which stripe drive triggered the event
	 * and increment error count for all stripes on that device.
	 * If the error count for a given device exceeds the threshold
	 * value we will no longer trigger any further events.
	 */
	for (i = 0; i < sc->stripes; i++)
		if (!strcmp(sc->stripe[i].dev->name, major_minor)) {
			atomic_inc(&(sc->stripe[i].error_count));
			if (atomic_read(&(sc->stripe[i].error_count)) <
			    DM_IO_ERROR_THRESHOLD)
				schedule_work(&sc->trigger_event);
		}

	return DM_ENDIO_DONE;
}

static int stripe_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct stripe_c *sc = ti->private;
	int ret = 0;
	unsigned i = 0;

	do {
		ret = fn(ti, sc->stripe[i].dev,
			 sc->stripe[i].physical_start,
			 sc->stripe_width, data);
	} while (!ret && ++i < sc->stripes);

	return ret;
}

static void stripe_io_hints(struct dm_target *ti,
			    struct queue_limits *limits)
{
	struct stripe_c *sc = ti->private;
	unsigned chunk_size = sc->chunk_size << SECTOR_SHIFT;

	blk_limits_io_min(limits, chunk_size);
	blk_limits_io_opt(limits, chunk_size * sc->stripes);
}

static struct target_type stripe_target = {
	.name   = "striped",
	.version = {1, 6, 0},
	.features = DM_TARGET_PASSES_INTEGRITY,
	.module = THIS_MODULE,
	.ctr    = stripe_ctr,
	.dtr    = stripe_dtr,
	.map    = stripe_map,
	.end_io = stripe_end_io,
	.status = stripe_status,
	.iterate_devices = stripe_iterate_devices,
	.io_hints = stripe_io_hints,
	.direct_access = stripe_dax_direct_access,
	.dax_copy_from_iter = stripe_dax_copy_from_iter,
	.dax_copy_to_iter = stripe_dax_copy_to_iter,
};

int __init dm_stripe_init(void)
{
	int r;

	r = dm_register_target(&stripe_target);
	if (r < 0)
		DMWARN("target registration failed");

	return r;
}

void dm_stripe_exit(void)
{
	dm_unregister_target(&stripe_target);
}
