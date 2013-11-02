#ifndef NITRO_H_
#define NITRO_H_

#include <linux/ioctl.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>

#define KVM_NITRO_NUM_VMS  	_IOR(KVMIO, 0xE0, __u64)

#endif //NITRO_H_