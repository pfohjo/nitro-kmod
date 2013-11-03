#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/list.h>
#include <linux/kvm_host.h>

extern raw_spinlock_t nitro_vm_lock;
extern struct list_head nitro_vm_list;

struct nitro_kvm_s{
  struct list_head list;
  pid_t creator;
  int vm_fd;
  struct kvm *kvm;
};

int nitro_iotcl_num_vms(void);
void nitro_create_vm(int,struct kvm*);
void nitro_destroy_vm(struct kvm*);

#endif //NITRO_MAIN_H_