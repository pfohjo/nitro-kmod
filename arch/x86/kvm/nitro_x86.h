#ifndef NITRO_X86_H_
#define NITRO_X86_H_

#include <linux/kvm_host.h>
#include <linux/nitro_main.h>

int nitro_set_syscall_trap(struct kvm*,unsigned long*,int);
int nitro_unset_syscall_trap(struct kvm*);

void nitro_wait(struct kvm*);
int nitro_report_syscall(struct kvm*, struct nitro_event*);
int nitro_report_sysret(struct kvm*, struct nitro_event*);
int nitro_report_event(struct kvm*);
inline u64 nitro_get_efer(struct kvm_vcpu*);
#endif //NITRO_X86_H_