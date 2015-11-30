#include "nitro_x86.h"

#include "x86.h"

#include <linux/nitro_main.h>
#include <linux/kernel.h>
#include <linux/completion.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);

/*
 * Assuming that no other thread is accessing the settings,
 * check if system call watching has already been disabled.
 * @param nitro	contains the system call settings
 * @return	true iff the settings specify neither specific system calls,
 *		nor that all system calls should be watched
 */
inline static bool _ignore_events(struct nitro *nitro)
{
	bool ignore;

	ignore = (nitro->system_call_bm == NULL) && !nitro->watch_all_syscalls;

	return ignore;
}

/*
 * Thread safe version of _ignore_events.
 * Check if system call watching has already been disabled.
 * @param nitro	contains the system call settings
 * @return	true iff the settings specify neither specific system calls,
 *		nor that all system calls should be watched
 */
inline static bool ignore_events(struct nitro *nitro)
{
	bool ignore;

	mutex_lock(&nitro->settings_lock);
	ignore = _ignore_events(nitro);
	mutex_unlock(&nitro->settings_lock);

	return ignore;
}

/*
 * Common function following the activation of any system call watching.
 * @param kvm	the virtual-machine-wide state to enable system call trapping
 *		for all vcpus
 */
static void nitro_activate_syscall_trap(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	u64 efer;
	struct msr_data msr_info;

	kvm->nitro.traps |= NITRO_TRAP_SYSCALL;
  
	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct nitro_vcpu *nitro_vcpu;

		nitro_vcpu_load(vcpu);

		nitro_vcpu = &vcpu->nitro;

		kvm_get_msr_common(vcpu, MSR_EFER, &efer);
		msr_info.index = MSR_EFER;
		msr_info.data = efer & ~EFER_SCE;
		msr_info.host_initiated = true;
		kvm_set_msr_common(vcpu, &msr_info);

		init_completion(&nitro_vcpu->k_wait_cv);
		mutex_init(&nitro_vcpu->k_wait_cv_lock);

		vcpu_put(vcpu);
	}
}

int nitro_set_syscall_trap(struct kvm *kvm, unsigned long *bitmap,
			   int system_call_max)
{
	struct nitro *nitro = &kvm->nitro;
	bool ignored;
	printk(KERN_INFO "nitro: set syscall trap\n");

	mutex_lock(&nitro->settings_lock);
	ignored = _ignore_events(nitro);
	if (!ignored)
		clear_syscall_settings(nitro);
	nitro->system_call_bm = bitmap;
	nitro->system_call_max = system_call_max;
	mutex_unlock(&nitro->settings_lock);

	if (ignored)
		nitro_activate_syscall_trap(kvm);

	return 0;
}

int nitro_set_all_syscall_trap(struct kvm *kvm)
{
	struct nitro *nitro = &kvm->nitro;
	bool ignored;
	printk(KERN_INFO "nitro: set all syscall trap\n");

	mutex_lock(&nitro->settings_lock);
	ignored = _ignore_events(nitro);
	nitro->watch_all_syscalls = true;
	if (nitro->system_call_bm != NULL) {
		kfree(nitro->system_call_bm);
		nitro->system_call_bm = NULL;
		nitro->system_call_max = 0;
	}
	mutex_unlock(&nitro->settings_lock);

	if (ignored)
		nitro_activate_syscall_trap(kvm);

	return 0;
}

/*
 * Remove an event entry from the hash table containing it, and free it.
 * @param event_entry	the event to remove and free
 */
static inline void free_event_entry(struct nitro_syscall_event_ht *event_entry)
{
	hash_del(&event_entry->ht);
	kfree(event_entry);
}

int nitro_add_process_trap(struct kvm *kvm, ulong process_cr3)
{
	struct nitro *nitro = &kvm->nitro;
	bool is_new = true;
	struct nitro_process_node *old_process;
	int ret;
	printk(KERN_INFO "nitro: add process trap\n");

	mutex_lock(&nitro->settings_lock);
	hash_for_each_possible(nitro->process_watch_ht, old_process, node,
			       process_cr3) {
		if(old_process->cr3 == process_cr3) {
			is_new = false;
			break;
		}
	}

	if (is_new) {
		struct nitro_process_node *
		new_process = kmalloc(sizeof(struct nitro_process_node),
				      GFP_KERNEL);

		if (new_process == NULL) {
			ret = -ENOMEM;
		} else {
			new_process->cr3 = process_cr3;
			printk(KERN_INFO "Going to add new process 0x%lx\n",
			       process_cr3);
			hash_add(nitro->process_watch_ht, &new_process->node,
				 process_cr3);
			ret = 0;
		}
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&nitro->settings_lock);

	return ret;
}

int nitro_remove_process_trap(struct kvm *kvm, ulong process_cr3)
{
	struct nitro *nitro = &kvm->nitro;
	struct nitro_process_node *process_node;
	bool found = false;
	printk(KERN_INFO "nitro: remove process trap\n");

	mutex_lock(&nitro->settings_lock);
	hash_for_each_possible(nitro->process_watch_ht, process_node, node,
			       process_cr3) {
		if(process_node->cr3 == process_cr3) {
			remove_process(process_node);
			found = true;
			break;
		}
	}
	mutex_unlock(&nitro->settings_lock);

	return found ? 0 : -EINVAL;
}

int nitro_unset_syscall_trap(struct kvm *kvm)
{
	struct nitro *nitro_kvm = &kvm->nitro;
	int i;
	struct kvm_vcpu *vcpu;
	u64 efer;
	struct msr_data msr_info;
	struct nitro_syscall_event_ht *ed;

	printk(KERN_INFO "nitro: unset syscall trap\n");

	clear_settings(nitro_kvm);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct nitro_vcpu *nitro_vcpu = &vcpu->nitro;
		nitro_vcpu->event = 0;

		/*
		 * Make sure there are no more calls to nitro_wait
		 * that could block nitro_vcpu_load.
		 */
		while (!mutex_trylock(&nitro_vcpu->k_wait_cv_lock))
			complete_all(&nitro_vcpu->k_wait_cv);

		nitro_vcpu_load(vcpu);
		mutex_unlock(&nitro_vcpu->k_wait_cv_lock);

		/* Clear any remaining events. */
		while (!down_trylock(&nitro_vcpu->n_wait_sem))
			;

		kvm_get_msr_common(vcpu, MSR_EFER, &efer);
		msr_info.index = MSR_EFER;
		msr_info.data = efer | EFER_SCE;
		msr_info.host_initiated = true;
		kvm_set_msr_common(vcpu, &msr_info);

		vcpu_put(vcpu);
	}

	nitro_kvm->traps &= ~(NITRO_TRAP_SYSCALL);

	hash_for_each(kvm->nitro.system_call_rsp_ht, i, ed, ht) {
		free_event_entry(ed);
	}

	return 0;
}

void nitro_wait(struct kvm_vcpu *vcpu)
{
	struct nitro_vcpu *nitro_vcpu = &vcpu->nitro;
	long rv;

	up(&nitro_vcpu->n_wait_sem);

	if (!mutex_trylock(&nitro_vcpu->k_wait_cv_lock))
		return;

	rv = wait_for_completion_interruptible_timeout(&nitro_vcpu->k_wait_cv,
						       msecs_to_jiffies(30000));
	mutex_unlock(&nitro_vcpu->k_wait_cv_lock);

	if (rv == 0)
		printk(KERN_INFO "nitro: %s: wait timed out\n", __FUNCTION__);
	else if (rv < 0)
		printk(KERN_INFO "nitro: %s: wait interrupted\n", __FUNCTION__);

	return;
}

int nitro_report_syscall(struct kvm_vcpu *vcpu)
{
	bool care = true;
	struct kvm *kvm;
	struct nitro *nitro_kvm;
	struct nitro_vcpu *nitro_vcpu;
	ulong syscall_event_cr3;
	unsigned long syscall_nr;
	struct nitro_syscall_event_ht *ed;

	kvm = vcpu->kvm;
	nitro_kvm = &kvm->nitro;
	nitro_vcpu = &vcpu->nitro;
	syscall_event_cr3 = nitro_vcpu->syscall_event_cr3;

	mutex_lock(&nitro_kvm->settings_lock);
	if (nitro_kvm->system_call_bm != NULL) {
		syscall_nr = kvm_register_read(vcpu, VCPU_REGS_RAX);

		if (syscall_nr > INT_MAX ||
		    syscall_nr > nitro_kvm->system_call_max ||
		    !test_bit((int) syscall_nr, nitro_kvm->system_call_bm))
			care = false;
	} else if (!nitro_kvm->watch_all_syscalls)
		care = false;

	/*
	 * Check if processes are specified, and if so,
	 * if the calling process is in the set of watched processes.
	 * If processes are not specified, report all processes
	 * that made a watched system call.
	 */
	if (care && !hash_empty(nitro_kvm->process_watch_ht)) {
		struct nitro_process_node *process_node;
		care = false;

		hash_for_each_possible(nitro_kvm->process_watch_ht,
				       process_node, node, syscall_event_cr3) {
			if (process_node->cr3 == syscall_event_cr3) {
				care = true;
				break;
			}
		}
	}
	mutex_unlock(&nitro_kvm->settings_lock);

	if (care) {
		ed = kzalloc(sizeof(struct nitro_syscall_event_ht),GFP_KERNEL);

		if (ed == NULL) {
			printk(KERN_INFO "nitro: %s: "
			       "Could not allocate space for new event.\n",
			       __FUNCTION__);
			return -ENOMEM;
		}

		ed->rsp = nitro_vcpu->syscall_event_rsp;
		ed->cr3 = syscall_event_cr3;
		nitro_hash_add(kvm, &ed, ed->rsp);

		memset(&nitro_vcpu->event_data, 0, sizeof(union event_data));
		nitro_vcpu->event_data.syscall = nitro_vcpu->syscall_event_rsp;

		nitro_wait(vcpu);
	}

	return 0;
}

int nitro_report_sysret(struct kvm_vcpu *vcpu){
	struct nitro_vcpu *nitro_vcpu = &vcpu->nitro;
	struct kvm *kvm;
	struct nitro_syscall_event_ht *ed;
	int ignore;

	kvm = vcpu->kvm;

	ignore = ignore_events(&kvm->nitro);

	if (ignore)
		return 0;

	hash_for_each_possible(kvm->nitro.system_call_rsp_ht, ed, ht,
			       nitro_vcpu->syscall_event_rsp) {
		if((ed->rsp == nitro_vcpu->syscall_event_rsp) &&
		   (ed->cr3 == nitro_vcpu->syscall_event_cr3)) {
			free_event_entry(ed);
      
			memset(&nitro_vcpu->event_data, 0,
			       sizeof(union event_data));
			nitro_vcpu->event_data.syscall = nitro_vcpu->
							 syscall_event_rsp;
      
			nitro_wait(vcpu);
			break;
		}
	}

	return 0;
}

int nitro_report_event(struct kvm_vcpu *vcpu)
{
	int r = 0;

	switch(vcpu->nitro.event) {
		case KVM_NITRO_EVENT_ERROR:
			if (ignore_events(&(vcpu->kvm->nitro))) {
				r = 0;
				break;
			}
			nitro_wait(vcpu);
			break;
		case KVM_NITRO_EVENT_SYSCALL:
			r = nitro_report_syscall(vcpu);
			break;
		case KVM_NITRO_EVENT_SYSRET:
			r = nitro_report_sysret(vcpu);
			break;
		default:
			printk(KERN_INFO "nitro: %s: "
			       "unknown event encountered (%d)\n", __FUNCTION__,
			       vcpu->nitro.event);
	}
	vcpu->nitro.event = 0;
	return r;
}

inline u64 nitro_get_efer(struct kvm_vcpu *vcpu){
  return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL) ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

