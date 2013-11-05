#ifndef NITRO_MAIN_H_
#define NITRO_MAIN_H_

#include <linux/list.h>
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/nitro.h>


struct nitro_kvm{
  int placeholder;//stuff will go here once we need it
};

struct kvm* nitro_get_vm_by_creator(pid_t);

int nitro_iotcl_num_vms(void);
int nitro_iotcl_attach_vcpus(struct kvm*, struct nitro_vcpus*);


void nitro_create_vm_hook(struct kvm*);
void nitro_destroy_vm_hook(struct kvm*);

#endif //NITRO_MAIN_H_