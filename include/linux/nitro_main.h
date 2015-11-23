#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/nitro.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>

#define NITRO_TRAP_SYSCALL 1UL
//#define NITRO_TRAP_XYZ  (1UL << 1)

/* nitro's part of the virtual-machine-wide state */
struct nitro {
	/* determines whether the syscall trap is globally set */
	uint32_t traps;
	/*
	 * lock for all of the below fields,
	 * which indicate which events to watch
	 */
	struct mutex settings_lock;
	/* Watch all system calls. Off by default. */
	bool watch_all_syscalls;
	/*
	 * If only a limited set of system calls are watched,
	 * this bitmap indicates them. NULL by default.
	 */
	unsigned long *system_call_bm;
	/*
	 * If only a limited set of system calls are watched,
	 * this integer indicates the highest one. 0 by default.
	 */
	unsigned int system_call_max;
	/* The prior syscall events, for checking against return events. */
	DECLARE_HASHTABLE(system_call_rsp_ht,7);
	/*
	 * The list of processes to watch, if any are specified.
	 * If none are specified, all processes are watched.
	 * Therefore this field does not determine
	 * if system call trapping should be active.
	 */
	DECLARE_HASHTABLE(process_watch_ht, 6);
};

/*
 * An entry in the process_watch_ht hash table of struct nitro,
 * Contains the cr3 value identifying the process.
 */
struct nitro_process_node {
	/* Identifies the watched process. */
	ulong cr3;
	/* node inside the hash table */
	struct hlist_node node;
};

/*
 * Remove and free a process from process_watch_ht.
 * @param process_node	the node holding the process to remove.
 */
inline static void remove_process(struct nitro_process_node *process_node)
{
	hash_del(&process_node->node);
	kfree(process_node);
}

/*
 * Stop watching any system calls.
 * @param nitro	contains the system call settings for the virtual machine
 */
inline static void clear_settings(struct nitro *nitro)
{
	struct nitro_process_node *process_node;
	int dummy_bkt;

	mutex_lock(&nitro->settings_lock);

	if (nitro->system_call_bm != NULL) {
		unsigned long *system_call_bm = nitro->system_call_bm;

		nitro->system_call_bm = NULL;
		nitro->system_call_max = 0;
		kfree(system_call_bm);
	} else if (nitro->watch_all_syscalls)
		nitro->watch_all_syscalls = false;

	hash_for_each(nitro->process_watch_ht, dummy_bkt, process_node, node) {
		remove_process(process_node);
	}

	mutex_unlock(&nitro->settings_lock);
}

/* the number of bits per bitmap word */
#define N_BITS_IN_BITMAP_WORD		(8 * sizeof(unsigned long))
/*
 * Round up the number of words required to store even the largest system call
 * in a bitmap.
 * @param system_call_max	the largest system call,
 *				which is one less than the
 *				unrounded number of needed bits
 * @return			number of words required
 *				to store the largest system call
 */
static inline unsigned n_words_in_syscall_bitmap(int system_call_max)
{
	return system_call_max / N_BITS_IN_BITMAP_WORD + 1;
}

struct nitro_syscall_event_ht{
  ulong rsp;
  ulong cr3;
  struct hlist_node ht;
};

/* nitro's part of the per-vcpu state */
struct nitro_vcpu {
	/*
	 * lock used to make sure that
	 * when nitro_unset_syscall_trap is between completing k_wait_cv
	 * and loading the vcpu,
	 * there is no call to nitro_wait that is holding the vcpu,
	 * and newly waiting on k_wait_cv
	 */
	struct mutex k_wait_cv_lock;
	/* After an event, suspend execution until the continue command. */
	struct completion k_wait_cv;
	/* Wait for event to fetch. */
	struct semaphore n_wait_sem;
	/* the event type */
	int event;
	/* additional event information */
	union event_data event_data;
	/* the last stack pointer identifies the system call for one task */
	ulong syscall_event_rsp;
	/* identifies the task */
	ulong syscall_event_cr3;
};


void nitro_hash_add(struct kvm*, struct nitro_syscall_event_ht**, ulong);
  
int nitro_vcpu_load(struct kvm_vcpu*);

struct kvm* nitro_get_vm_by_creator(pid_t);

int nitro_ioctl_num_vms(void);
int nitro_ioctl_attach_vcpus(struct kvm*, struct nitro_vcpus*);


void nitro_create_vm_hook(struct kvm*);
void nitro_destroy_vm_hook(struct kvm*);
void nitro_create_vcpu_hook(struct kvm_vcpu*);
void nitro_destroy_vcpu_hook(struct kvm_vcpu*);

int nitro_ioctl_get_event(struct kvm_vcpu*);
int nitro_ioctl_continue(struct kvm_vcpu*);

inline int nitro_is_trap_set(struct kvm*, uint32_t);


#endif //NITRO_MAIN_H_
