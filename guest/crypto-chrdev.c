/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 * Modified by Alexandros Kalomoiros
 */
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/wait.h>

#include "crypto-chrdev.h"
#include "crypto.h"
#include "debug.h"

#include "cryptodev.h"

#define MSG_LEN 100

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor) {
    struct crypto_device *crdev;
    unsigned long flags;

    debug("Entering");

    spin_lock_irqsave(&crdrvdata.lock, flags);
    list_for_each_entry(crdev, &crdrvdata.devs, list) {
        if (crdev->minor == minor)
            goto out;
    }
    crdev = NULL;

out:
    spin_unlock_irqrestore(&crdrvdata.lock, flags);

    debug("Leaving");
    return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp) {
    int ret = 0;
    int err;
    unsigned int len, num_out, num_in;
    struct crypto_open_file *crof;
    struct crypto_device *crdev;
    struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];

    unsigned int *syscall_type;
    int *host_fd;

    debug("Entering");

    ret = -ENODEV;
    if ((ret = nonseekable_open(inode, filp)) < 0)
        goto fail;

    /* Associate this open file with the relevant crypto device. */
    crdev = get_crypto_dev_by_minor(iminor(inode));
    if (!crdev) {
        debug("Could not find crypto device with %u minor", iminor(inode));
        ret = -ENODEV;
        goto fail;
    }

    crof = kzalloc(sizeof(*crof), GFP_KERNEL);
    if (!crof) {
        ret = -ENOMEM;
        goto fail;
    }
    crof->crdev = crdev;
    crof->host_fd = -1;
    filp->private_data = crof;

    /**
     * We need two sg lists, one for syscall_type and one to get the
     * file descriptor from the host.
     **/

    syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
    *syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;

    host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
    *host_fd = -1;

    num_in = 0;
    num_out = 0;

    sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
    sgs[num_out++] = &syscall_type_sg;

    sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
    sgs[num_out + num_in++] = &host_fd_sg;

    /* Going into critical section. We need to lock */

    if (down_interruptible(&crdev->lock))
        return -ERESTARTSYS;

    err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg,
                            GFP_ATOMIC);
    virtqueue_kick(crdev->vq);
    while (virtqueue_get_buf(crdev->vq, &len) == NULL)
        /* do nothing */;

    up(&crdev->lock);

    /*
    ** Unlock the Semaphore.
    ** If host failed to open() return -ENODEV.
    */

    if (*host_fd < 0) {
        ret = -ENODEV;
        goto fail;
    }

    crof->host_fd = *host_fd;

    kfree(syscall_type);
    kfree(host_fd);

fail:
    debug("Leaving");
    return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp) {
    int ret = 0;
    int err;
    unsigned int len, num_out, num_in;
    struct crypto_open_file *crof = filp->private_data;
    struct crypto_device *crdev = crof->crdev;
    unsigned int *syscall_type;
    int *host_fd;
    struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
    debug("Entering");

    /**
     * Send data to the host.
     **/
    syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
    *syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

    host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
    *host_fd = crof->host_fd;

    num_in = 0;
    num_out = 0;

    sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
    sgs[num_out++] = &syscall_type_sg;

    sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
    sgs[num_out++] = &host_fd_sg;

    /**
     * Wait for the host to process our data.
     **/

    /*
    ** Going into critical section.
    */

    if (down_interruptible(&crdev->lock))
        return -ERESTARTSYS;

    err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg,
                            GFP_ATOMIC);
    virtqueue_kick(crdev->vq);
    while (virtqueue_get_buf(crdev->vq, &len) == NULL)
        /* do nothing */;

    up(&crdev->lock);

    /* Unlock and return */

    if (*host_fd < 0)
        ret = -1;

    kfree(syscall_type);
    kfree(host_fd);
    kfree(crof);
    debug("Leaving");
    return ret;
}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd,
                                unsigned long arg) {
    long ret = 0;
    unsigned long flags;
    int err, *host_fd, *host_ret;
    unsigned int num_out, num_in, len, *cmdpointer, *syscall_type;
    unsigned char *source, *dest, *iv, *session_key, *temp;
    uint32_t *ses_id;

    struct crypto_open_file *crof = filp->private_data;
    struct crypto_device *crdev = crof->crdev;
    struct virtqueue *vq = crdev->vq;
    struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, cmd_sg,
        session_sg, host_fd_sg, host_ret_sg, session_id_sg, cryp_src_sg,
        cryp_dst_sg, cryp_iv_sg, cryp_op_sg, sessionkey_sg, *sgs[13];
    struct session_op *session;
    struct crypt_op *cryp;

    debug("Entering");

    num_out = 0;
    num_in = 0;
    session_key = NULL;
    source = NULL;
    dest = NULL;
    iv = NULL;
    temp = NULL;

    /* Do memory allocations */

    ses_id = kmalloc(sizeof(*ses_id), GFP_KERNEL);

    cmdpointer = kmalloc(sizeof(*cmdpointer), GFP_KERNEL);
    *cmdpointer = cmd;

    host_ret = kmalloc(sizeof(*host_ret), GFP_KERNEL);

    syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
    *syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;

    session = kmalloc(sizeof(*session), GFP_KERNEL);

    cryp = kmalloc(sizeof(*cryp), GFP_KERNEL);

    host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
    *host_fd = crof->host_fd;

    /**
     *  These are common to all ioctl commands.
     **/

    sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
    sgs[num_out++] = &syscall_type_sg;

    sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
    sgs[num_out++] = &host_fd_sg;

    /**
     *  Add all the cmd specific sg lists.
     **/
    switch (cmd) {
    case CIOCGSESSION: // Get Session
        debug("CIOCGSESSION");

        sg_init_one(&cmd_sg, cmdpointer, sizeof(*cmdpointer));
        sgs[num_out++] = &cmd_sg;

        err =
            copy_from_user(session, (struct session_op *)arg, sizeof(*session));
        if (err) {
            debug("CAN'T GET SESSION FROM IOCTL");
            ret = -1;
            goto fail;
        }

        session_key = kmalloc(session->keylen * sizeof(char), GFP_KERNEL);
        if (!session_key) {
            ret = -ENOMEM;
            goto fail;
        }

        if (copy_from_user(session_key, session->key,
                           sizeof(char) * session->keylen)) {
            debug("CAN'T GET KEY");
            ret = -1;
            goto fail;
        }

        sg_init_one(&sessionkey_sg, session_key,
                    sizeof(char) * session->keylen);
        sgs[num_out++] = &sessionkey_sg;

        sg_init_one(&session_sg, session, sizeof(*session));
        sgs[num_out + num_in++] = &session_sg;

        sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
        sgs[num_out + num_in++] = &host_ret_sg;

        break;

    case CIOCFSESSION: // Close Session
        debug("CIOCFSESSION");

        sg_init_one(&cmd_sg, cmdpointer, sizeof(*cmdpointer));
        sgs[num_out++] = &cmd_sg;

        if (copy_from_user(ses_id, (uint32_t *)arg, sizeof(*ses_id))) {
            debug("CAN'T GET SESSION ID");
            ret = -1;
            goto fail;
        }

        sg_init_one(&session_id_sg, ses_id, sizeof(*ses_id));
        sgs[num_out++] = &session_id_sg;

        sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
        sgs[num_out + num_in++] = &host_ret_sg;

        break;

    case CIOCCRYPT: // Encrypt/Decrypt
        debug("CIOCCRYPT");

        sg_init_one(&cmd_sg, cmdpointer, sizeof(*cmdpointer));
        sgs[num_out++] = &cmd_sg;

        if (copy_from_user(cryp, (struct crypt_op *)arg, sizeof(*cryp))) {
            debug("CANT GET CRYPOP");
            ret = -1;
            goto fail;
        }

        sg_init_one(&cryp_op_sg, cryp, sizeof(*cryp));
        sgs[num_out++] = &cryp_op_sg;

        source = kmalloc(cryp->len * sizeof(char), GFP_KERNEL);
        if (copy_from_user(source, cryp->src, cryp->len * sizeof(char))) {
            debug("CANT GET SOURCE");
            ret = -1;
            goto fail;
        }

        sg_init_one(&cryp_src_sg, source, cryp->len * sizeof(char));
        sgs[num_out++] = &cryp_src_sg;

        iv = kmalloc(16 * sizeof(char), GFP_KERNEL);
        if (copy_from_user(iv, cryp->iv, 16 * sizeof(char))) {
            debug("CANT GET IV");
            ret = -1;
            goto fail;
        }

        sg_init_one(&cryp_iv_sg, iv, cryp->len * sizeof(char));
        sgs[num_out++] = &cryp_iv_sg;

        temp = cryp->dst;
        dest = kmalloc(cryp->len * sizeof(char), GFP_KERNEL);
        sg_init_one(&cryp_dst_sg, dest, cryp->len * sizeof(char));
        sgs[num_out + num_in++] = &cryp_dst_sg;

        sg_init_one(&host_ret_sg, host_ret, sizeof(*host_ret));
        sgs[num_out + num_in++] = &host_ret_sg;

        break;

    default:
        debug("Unsupported ioctl command");
        break;
    }

    /**
     * Wait for the host to process our data.
     **/

    /* Lock!!! Critical section */

    if (down_interruptible(&crdev->lock))
        return -ERESTARTSYS;

    err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg,
                            GFP_ATOMIC);
    virtqueue_kick(vq);
    while (virtqueue_get_buf(vq, &len) == NULL)
        /* do nothing */;

    up(&crdev->lock);

    // Return to user the thing he needs!

    switch (cmd) {
    case CIOCGSESSION: // Get Session
        debug("Return from CIOCGSESSION");
        if (copy_to_user((struct session_op *)arg, session, sizeof(*session))) {
            debug("FAILED TO START A SESSION");
            ret = -1;
            goto fail;
        }

        kfree(session_key);
        break;

    case CIOCFSESSION: // Close Session

        debug("Return from CIOCFSESSION");
        break;

    case CIOCCRYPT: // Encrypt/Decrypt
        debug("Return from CIOCCRYPT");

        if (copy_to_user(temp, dest, cryp->len * sizeof(char))) {
            debug("FAILED TO ENCRYPT/DECRYPT YOUR DATA");
            ret = -1;
            goto fail;
        }

        kfree(source);
        kfree(iv);
        kfree(dest);
        break;
    }

    kfree(ses_id);
    kfree(cmdpointer);
    kfree(host_fd);
    kfree(host_ret);
    kfree(session);
    kfree(cryp);
    kfree(syscall_type);
fail:

    debug("Leaving");

    return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf,
                                  size_t cnt, loff_t *f_pos) {
    debug("Entering");
    debug("Leaving");
    return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = {
    .owner = THIS_MODULE,
    .open = crypto_chrdev_open,
    .release = crypto_chrdev_release,
    .read = crypto_chrdev_read,
    .unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void) {
    int ret;
    dev_t dev_no;
    unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

    debug("Initializing character device...");
    cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
    crypto_chrdev_cdev.owner = THIS_MODULE;

    dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
    ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
    if (ret < 0) {
        debug("failed to register region, ret = %d", ret);
        goto out;
    }
    ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
    if (ret < 0) {
        debug("failed to add character device");
        goto out_with_chrdev_region;
    }

    debug("Completed successfully");
    return 0;

out_with_chrdev_region:
    unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
    return ret;
}

void crypto_chrdev_destroy(void) {
    dev_t dev_no;
    unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

    debug("entering");
    dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
    cdev_del(&crypto_chrdev_cdev);
    unregister_chrdev_region(dev_no, crypto_minor_cnt);
    debug("leaving");
}
