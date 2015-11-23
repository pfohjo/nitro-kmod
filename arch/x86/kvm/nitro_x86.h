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
/*
 * Start watching a process, identified by its cr3 value.
 * This function does not activate system call trapping,
 * and therefore can be run at any time.
 * @param kvm		the virtual-machine-wide state
 *			containing the system call settings
 * @param process_cr3	the identifier for the process to watch
 * @return		0 on success,
 *			-ENOMEM if no space could be allocated
 *				for the new process,
 *			-EINVAL if the process is already watched
 */
int nitro_add_process_trap(struct kvm *kvm, ulong process_cr3);
/*
 * Stop watching a process, identified by its cr3 value.
 * If that was the last process, all processes will be watched,
 * and therefore can be run at any time.
 * This function does not deactivate system call trapping.
 * @param kvm		the virtual-machine-wide state
 *			containing the system call settings
 * @param process_cr3	the identifier for the process to unwatch
 * @return		0 on success,
 *			-EINVAL if the process was not previously watched
 */
int nitro_remove_process_trap(struct kvm *kvm, ulong process_cr3);
int nitro_unset_syscall_trap(struct kvm *kvm);

void nitro_wait(struct kvm_vcpu*);
int nitro_report_syscall(struct kvm_vcpu*);
int nitro_report_sysret(struct kvm_vcpu*);
int nitro_report_event(struct kvm_vcpu*);
inline u64 nitro_get_efer(struct kvm_vcpu*);
#endif //NITRO_X86_H_
