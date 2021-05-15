#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "util.h"
#include "net.h"
#include "ether.h"

#include "ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

struct ether_tap {
    char name[IFNAMSIZ];
    int fd;
};

#define PRIV(x) ((struct ether_tap *)x->priv)

static int
ether_tap_addr(struct net_device *dev)
{

}

static int
ether_tap_open(struct net_device *dev)
{

}

static int
ether_tap_close(struct net_device *dev)
{

}

static ssize_t
ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{

}

int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void dst)
{

}

static ssize_t
ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{

}

static int
ether_tap_poll(struct net_device *dev)
{

}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
    .poll = ether_tap_poll,
};

struct net_device *
ether_tap_init(const char *name, const char *addr)
{
    struct net_device *dev;
    struct ether_tap *tap;

    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    ether_setup_helper(dev);
    if (addr) {
        if (ether_addr_pton(addr, dev->addr) == -1) {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    dev->ops = &ether_tap_ops;
    tap = calloc(1, sizeof(*tap));
    if (!tap) {
        errorf("calloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name)-1);
    tap->fd = -1;
    dev->priv = tap;
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        free(tap);
        return NULL;
    }
    debugf("ethernet device initialized, dev=%s", dev->name);
    return dev;
}