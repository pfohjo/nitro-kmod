#ifndef NITRO_H_
#define NITRO_H_

#include <linux/ioctl.h>
#include <linux/kvm.h>
#include <linux/types.h>

#define NITRO_MAX_VCPUS 64

struct nitro_vcpus{
  int num_vcpus;
  int ids[NITRO_MAX_VCPUS];
  int fds[NITRO_MAX_VCPUS];
};

struct nitro_syscall_trap{
  int *syscalls;
  int size;
};

union event_data{
  ulong syscall;
};

//events
#define KVM_NITRO_EVENT_ERROR			1
#define KVM_NITRO_EVENT_SYSCALL			2
#define KVM_NITRO_EVENT_SYSRET			3

//KVM functions
#define KVM_NITRO_NUM_VMS  	_IO(KVMIO, 0xE0)
#define KVM_NITRO_ATTACH_VM  	_IOW(KVMIO, 0xE1, pid_t)

//VM functions
#define KVM_NITRO_ATTACH_VCPUS		_IOR(KVMIO, 0xE2, struct nitro_vcpus)
#define KVM_NITRO_SET_SYSCALL_TRAP	_IOW(KVMIO, 0xE3, \
					     struct nitro_syscall_trap)
#define KVM_NITRO_UNSET_SYSCALL_TRAP	_IO(KVMIO, 0xE4)
#define KVM_NITRO_SET_ALL_SYSCALL_TRAP	_IO(KVMIO, 0xE5)

//VCPU functions
#define KVM_NITRO_GET_EVENT	_IOR(KVMIO, 0xE8, union event_data)
#define KVM_NITRO_CONTINUE	_IO(KVMIO, 0xE9)

#define KVM_NITRO_GET_REGS              _IOR(KVMIO,  0xEA, struct kvm_regs)
#define KVM_NITRO_SET_REGS              _IOW(KVMIO,  0xEB, struct kvm_regs)
#define KVM_NITRO_GET_SREGS             _IOR(KVMIO,  0xEC, struct kvm_sregs)
#define KVM_NITRO_SET_SREGS             _IOW(KVMIO,  0xED, struct kvm_sregs)
#define KVM_NITRO_TRANSLATE		_IOWR(KVMIO, 0xEF, \
					      struct kvm_translation)

#endif //NITRO_H_
