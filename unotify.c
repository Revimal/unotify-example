#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/srcu.h>

#define UNOTIFY_NAME "unotify"
#define UNOTIFY_VER "1.0.0"
#define UNOTIFY_MVER "unreleased"
#define UNOTIFY_YEAR "2019"
#define UNOTIFY_VERSION UNOTIFY_VER "-" UNOTIFY_MVER
#define UNOTIFY_DESCMSG "User-process notifier sample module."
#define UNOTIFY_AUTHOR "Hyeonho Seo (seohho@gmail.com)"
#define UNOTIFY_LICENSE "Dual MIT/GPL"

static const char unotify_name[] =
	UNOTIFY_NAME;
static const char unotify_version[] =
	UNOTIFY_VERSION;
static const char unotify_descmsg[] =
	UNOTIFY_DESCMSG;
static const char unotify_copyright[] =
	"Copyright (c) " UNOTIFY_YEAR " " UNOTIFY_AUTHOR;

#define UNOTIFY_MAXDEV (1U << MINORBITS)
#define UNOTIFY_HASHBIT (9)

struct unotify_desc
{
	struct hlist_node node;
	struct rcu_head rcu;

	pid_t pid;
	struct wait_queue_head waitq;
	atomic_t trigger;
};

static int unotify_major;
static struct cdev *unotify_cdev;
static struct class *unotify_class;
static struct device *unotify_device;

static int unotify_clean;
DEFINE_STATIC_SRCU( unotify_srcu );
static DEFINE_MUTEX( unotify_mutex );
static DEFINE_HASHTABLE( unotify_hash, UNOTIFY_HASHBIT );

static inline u32 unotify_phash( pid_t pid )
{
	return hash_long( (unsigned long)pid, UNOTIFY_HASHBIT );
}

static void unotify_reclaim( struct rcu_head *rcu )
{
	struct unotify_desc *wait_desc =
		container_of( rcu, struct unotify_desc, rcu );

	kfree( wait_desc );

	return;
}

static int unotify_open( struct inode *inode, struct file *filep )
{
	const pid_t current_pid = current->pid;
	const u32 current_hash = unotify_phash( current_pid );
	struct unotify_desc *wait_desc;

	mutex_lock( &unotify_mutex );

	if ( unlikely( !!unotify_clean ) )
	{
		mutex_unlock( &unotify_mutex );

		return -ECANCELED;
	}

	wait_desc = kzalloc( sizeof(struct unotify_desc), GFP_KERNEL );
	if ( !wait_desc )
	{
		mutex_unlock( &unotify_mutex );

		return -ENOMEM;
	}

	wait_desc->pid = current_pid;
	init_waitqueue_head( &wait_desc->waitq );
	atomic_set( &wait_desc->trigger, 0);

	hash_add_rcu( unotify_hash, &wait_desc->node, current_hash );

	mutex_unlock( &unotify_mutex );

	return 0;
}

static int unotify_release( struct inode *inode, struct file *filep )
{
	const pid_t current_pid = current->pid;
	const u32 current_hash = unotify_phash( current_pid );
	struct unotify_desc *wait_desc;

	mutex_lock( &unotify_mutex );

	if ( unlikely( !!unotify_clean ) )
	{
		mutex_unlock( &unotify_mutex );

		return -ECANCELED;
	}

	hash_for_each_possible( unotify_hash,
			wait_desc, node, current_hash )
	{
		if ( wait_desc->pid == current_pid )
		{
			atomic_set( &wait_desc->trigger, 1 );
			wake_up_interruptible( &wait_desc->waitq );

			hash_del_rcu( &wait_desc->node );

			call_srcu( &unotify_srcu,
					&wait_desc->rcu, unotify_reclaim );

			mutex_unlock( &unotify_mutex );
			return 0;
		}
	}

	mutex_unlock( &unotify_mutex );

	return -ENOENT;
}

static long unotify_ioctl( struct file *filep,
	unsigned int wake_cmd, unsigned long ultype_pid )
{
	int srcu_idx;

	rcu_read_lock();

	if ( unlikely( !!unotify_clean ) )
	{
		rcu_read_unlock();

		return -ECANCELED;
	}

	srcu_idx = srcu_read_lock( &unotify_srcu );

	rcu_read_unlock();

	if ( !wake_cmd )
	{
		/* WAIT */
		const pid_t current_pid = current->pid;
		const u32 current_hash = unotify_phash( current_pid );
		struct unotify_desc *wait_desc;

		hash_for_each_possible_rcu( unotify_hash,
			wait_desc, node, current_hash )
		{
			if ( wait_desc->pid == current_pid )
			{
				wait_event_interruptible( wait_desc->waitq,
						!!atomic_cmpxchg( &wait_desc->trigger, 1, 0 ) );

				srcu_read_unlock( &unotify_srcu, srcu_idx );

				return 0;
			}
		}
	}
	else
	{
		/* WAKE */
		const pid_t target_pid = (const pid_t)ultype_pid;
		const u32 target_hash = unotify_phash( target_pid );
		struct unotify_desc *wait_desc;

		hash_for_each_possible_rcu( unotify_hash,
				wait_desc, node, target_hash )
		{
			if ( wait_desc->pid == target_pid )
			{
				atomic_set( &wait_desc->trigger, 1 );
				wake_up_interruptible( &wait_desc->waitq );

				srcu_read_unlock( &unotify_srcu, srcu_idx );

				return 0;
			}
		}
	}

	srcu_read_unlock( &unotify_srcu, srcu_idx );

	return -ENOENT;
}

static const struct file_operations unotify_fops = {
	.owner = THIS_MODULE,
	.open = unotify_open,
	.release = unotify_release,
	.unlocked_ioctl = unotify_ioctl,
};

static int __init unotify_init( void )
{
	struct cdev *cdev = NULL;
	dev_t unotify_dev = 0;
	int ret;

	pr_info( "%s - v%s\n", unotify_name, unotify_version );
	pr_info( "%s\n", unotify_descmsg );
	pr_info( "%s\n", unotify_copyright );

	ret = alloc_chrdev_region( &unotify_dev, 0,
			UNOTIFY_MAXDEV, unotify_name );
	if ( ret )
	{
		goto err;
	}

	ret = -ENOMEM;
	cdev = cdev_alloc();
	if ( !cdev )
	{
		goto err_unregister_region;
	}

	cdev->owner = THIS_MODULE;
	cdev->ops = &unotify_fops;
	kobject_set_name( &cdev->kobj, "%s", unotify_name );

	ret = cdev_add( cdev, unotify_dev, UNOTIFY_MAXDEV );
	if ( ret )
	{
		goto err_put_kobject;
	}

	unotify_major = MAJOR( unotify_dev );
	unotify_cdev = cdev;

	unotify_class = class_create( THIS_MODULE, unotify_name );
	if ( IS_ERR( unotify_class ) )
	{
		ret = PTR_ERR( unotify_class );
		goto err_del_cdev;
	}

	unotify_device = device_create( unotify_class, NULL,
			MKDEV( unotify_major, 0 ), NULL, unotify_name );
	if ( IS_ERR( unotify_device ) )
	{
		ret = PTR_ERR( unotify_device );
		goto err_destroy_class;
	}

	return 0;

err_destroy_class:
	class_destroy( unotify_class );
err_del_cdev:
	cdev_del( unotify_cdev );
err_put_kobject:
	kobject_put( &cdev->kobj );
err_unregister_region:
	unregister_chrdev_region( unotify_dev, UNOTIFY_MAXDEV );
err:
	return ret;
}

static void __exit unotify_exit( void )
{
	struct unotify_desc *wait_desc;
	struct hlist_node *temp_node;
	int bkt;

	device_destroy( unotify_class, MKDEV( unotify_major, 0 ) );
	class_destroy( unotify_class );
	cdev_del( unotify_cdev );
	unregister_chrdev_region( MKDEV( unotify_major, 0 ), UNOTIFY_MAXDEV );

	mutex_lock( &unotify_mutex );
	unotify_clean = 1;
	mutex_unlock( &unotify_mutex );

	synchronize_rcu();
	synchronize_srcu( &unotify_srcu );

	hash_for_each_safe( unotify_hash, bkt, temp_node, wait_desc, node )
	{
		atomic_set( &wait_desc->trigger, 1 );
		wake_up_interruptible( &wait_desc->waitq );

		hash_del_rcu( &wait_desc->node );

		call_srcu( &unotify_srcu,
				&wait_desc->rcu, unotify_reclaim );
	}

	srcu_barrier( &unotify_srcu );

	return;
}

module_init( unotify_init );
module_exit( unotify_exit );

MODULE_VERSION( UNOTIFY_VERSION );
MODULE_LICENSE( UNOTIFY_LICENSE );
MODULE_AUTHOR( UNOTIFY_AUTHOR );
MODULE_DESCRIPTION( UNOTIFY_DESCMSG );
