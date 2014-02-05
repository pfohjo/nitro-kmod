#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/nitro.h>
#include <linux/hashtable.h>
#include <linux/list.h>

#define NITRO_TRAP_SYSCALL 1UL
//#define NITRO_TRAP_XYZ  (1UL << 1)

struct nitro_syscall_event_ht{
  ulong rsp;
  ulong cr3;
  struct hlist_node ht;
};

struct nitro_event{
  struct list_head q;
  atomic_t num_waiters;
  unsigned int event_id;
  ulong syscall_event_nr;
  ulong syscall_event_rsp;
  ulong syscall_event_cr3;
  
  union event_data user_event_data;
};

struct nitro{
  spinlock_t nitro_lock;
  
  uint32_t traps; //determines which traps are set (e.g., traps | NITRO_TRAP_SYSCALL)
  
  struct completion k_wait_cv;
  struct semaphore n_wait_sem;
  
  struct list_head event_q;
  
  //system call trap related stuff
  unsigned long *system_call_bm; //bitmap determining which system calls to report to userspace
  unsigned int system_call_max;  //the max system call (determines size of system_call_bm)
  DECLARE_HASHTABLE(system_call_rsp_ht,7); //hashtable responsible for matching system calls with returns
  
  
  
};

struct nitro_vcpu{
  
};


void nitro_hash_add(struct kvm*, struct nitro_syscall_event_ht**, ulong);
void nitro_complete_all(struct kvm*, struct completion*);
void nitro_complete_rest(struct kvm*, struct completion*);
  
int nitro_vcpu_load(struct kvm_vcpu*);

struct kvm* nitro_get_vm_by_creator(pid_t);

int nitro_iotcl_num_vms(void);
int nitro_iotcl_attach_vcpus(struct kvm*, struct nitro_vcpus*);


void nitro_create_vm_hook(struct kvm*);
void nitro_destroy_vm_hook(struct kvm*);
void nitro_create_vcpu_hook(struct kvm_vcpu*);
void nitro_destroy_vcpu_hook(struct kvm_vcpu*);

int nitro_ioctl_get_event(struct kvm*, void*);
int nitro_ioctl_continue(struct kvm*);

inline int nitro_is_trap_set(struct kvm*, uint32_t);


#endif //NITRO_MAIN_H_