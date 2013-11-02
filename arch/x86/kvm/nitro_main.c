#include <linux/spinlock.h>
#include <linux/list.h>

#include <linux/kvm_host.h>

#include <linux/nitro_main.h>

int nitro_iotcl_num_vms(void){
  struct kvm *kvm;
  int rv = 0;
  
  raw_spin_lock(&kvm_lock);
  list_for_each_entry(kvm, &vm_list, vm_list)
    rv++;
  raw_spin_unlock(&kvm_lock);
  
  return rv;
}