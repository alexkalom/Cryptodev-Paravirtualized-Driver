/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * Modified by Alexandros Kalomoiros
 *
 */

#include "hw/virtio/virtio-crypto.h"
#include "hw/virtio/virtio-serial.h"
#include <crypto/cryptodev.h>
#include <fcntl.h>
#include <qemu/iov.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features) {
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data) { DEBUG_IN(); }

static void set_config(VirtIODevice *vdev, const uint8_t *config_data) {
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status) { DEBUG_IN(); }

static void vser_reset(VirtIODevice *vdev) { DEBUG_IN(); }

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq) {
    VirtQueueElement elem;
    unsigned int *syscall_type;

    DEBUG_IN();

    if (!virtqueue_pop(vq, &elem)) {
        DEBUG("No item to pop from VQ :(");
        return;
    }

    DEBUG("I have got an item from VQ :)");
    // elem.out_sg.iov_base or elem.in_sg.iov_base are POINTERS so care
    // !!!!!!!!!!
    syscall_type = elem.out_sg[0].iov_base; // R flag so out, we have to read it
    int *host_fd;
    switch (*syscall_type) {
    case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
        host_fd = elem.in_sg[0].iov_base; // host_fd is now a pointer to host_fd
                                          // , W flag so we will return it
        *host_fd = open("/dev/crypto", O_RDWR);
        if ((*host_fd) < 0) {
            perror("open(/dev/crypto)");
            return;
        }
        break;

    case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
        host_fd = elem.out_sg[1].iov_base; // host_fd is now a pointer to
                                           // host_fd ,we have to read it
        if (close(*host_fd) < 0) {
            *host_fd = -1;
            perror("close");
            return;
        }
        break;

    case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
        /* ?? */
        // unsigned char *output_msg = elem.out_sg[1].iov_base;
        // unsigned char *input_msg = elem.in_sg[0].iov_base;
        // memcpy(input_msg, "Host: Welcome to the virtio World!", 35);
        // printf("Guest says: %s\n", output_msg);
        // printf("We say: %s\n", input_msg);

        unsigned int *ioctl_cmd =
            elem.out_sg[2].iov_base;               // common for all three
        int *host_return = elem.in_sg[1].iov_base; // -1 if something goes wrong

        switch (*ioctl_cmd) {
        case CIOCGSESSION:
            DEBUG("Backend starting a crypto session");
            host_fd = elem.out_sg[1].iov_base;
            unsigned char *session_key = elem.out_sg[3].iov_base;
            struct session_op *session_op_st = elem.in_sg[0].iov_base;
            session_op_st->key = session_key;
            if (ioctl(*host_fd, CIOCGSESSION, session_op_st)) {
                *host_return = -1;
                perror("Backend crypto session fail starting");

            } else {
                *host_return = 0;
                DEBUG("Backend crypto session starting succesfully");
            }
            break;

        case CIOCFSESSION:
            DEBUG("Backend ending a crypto session");
            host_fd = elem.out_sg[1].iov_base;
            uint32_t *ses_id = elem.out_sg[3].iov_base;
            if (ioctl(*host_fd, CIOCFSESSION, ses_id)) {
                *host_return = -1;
                perror("Backend crypto session fail ending");
            } else {
                *host_return = 0;
                DEBUG("Backend crypto session ending succesfully");
            }
            break;
        case CIOCCRYPT:
            DEBUG("Backend encrypting/decrypting");
            host_fd = elem.out_sg[1].iov_base;
            struct crypt_op *crypt_operands = elem.out_sg[3].iov_base;
            unsigned char *source = elem.out_sg[4].iov_base;
            unsigned char *iv = elem.out_sg[5].iov_base;
            unsigned char *destination = elem.in_sg[0].iov_base;
            crypt_operands->src = source;
            crypt_operands->dst = destination;
            crypt_operands->iv = iv;

            if (ioctl(*host_fd, CIOCCRYPT, crypt_operands)) {
                perror("Backend fail ioctl(CIOCCRYPT)");
                *host_return = -1;
            } else {
                *host_return = 0;
                DEBUG("Backend encrypting/decrypting succesful");
            }
            break;

        default:
            DEBUG("We don't support this ioctl command");
            break;
        }
        break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }

    virtqueue_push(vq, &elem, 0);
    virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp) {
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp) {
    DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name = TYPE_VIRTIO_CRYPTO,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void) {
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
