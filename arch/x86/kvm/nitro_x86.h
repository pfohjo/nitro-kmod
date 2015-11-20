#ifndef NITRO_X86_H_
#define NITRO_X86_H_

#include <linux/kvm_host.h>

int nitro_set_syscall_trap(struct kvm *kvm, unsigned long *bitmap,
			   int system_call_max);
/*
 * Enable watching all system calls.
 * @param kvm	the virtual-machine-wide state
 *		containing the system call settings
 * @return	0
 */
int nitro_set_all_syscall_trap(struct kvm *kvm);
int nitro_unset_syscall_trap(struct kvm *kvm);

void nitro_wait(struct kvm_vcpu*);
int nitro_report_syscall(struct kvm_vcpu*);
int nitro_report_sysret(struct kvm_vcpu*);
int nitro_report_event(struct kvm_vcpu*);
inline u64 nitro_get_efer(struct kvm_vcpu*);
#endif //NITRO_X86_H_
