#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/compiler.h>
#include <asm/current.h>
#include <asm-generic/errno-base.h>
#include <linux/preempt.h>
#include <linux/hashtable.h>

#include <linux/kvm_host.h>

#include <linux/nitro_main.h>
#include <net/irda/parameters.h>

extern int create_vcpu_fd(struct kvm_vcpu*);

void nitro_hash_add(struct kvm *kvm, struct nitro_syscall_event_ht **hnode, ulong key){
  struct nitro_syscall_event_ht *ed;
  
  
  hash_for_each_possible(kvm->nitro.system_call_rsp_ht, ed, ht, key){
    if((ed->rsp == (*hnode)->rsp) && (ed->cr3 == (*hnode)->cr3)){
      kfree(*hnode);
      hnode = &ed;
      return;
    }
  }
  
  hash_add(kvm->nitro.system_call_rsp_ht,&((*hnode)->ht),key);
  return;
}

void nitro_complete_all(struct kvm *kvm, struct completion *x){
  unsigned long flags;
  
  spin_lock_irqsave(&x->wait.lock, flags);
  x->done += atomic_read(&kvm->online_vcpus);
  __wake_up_locked(&x->wait, TASK_NORMAL, 0);
  spin_unlock_irqrestore(&x->wait.lock, flags);
}

void nitro_complete_rest(struct kvm *kvm, struct completion *x){
  unsigned long flags;
  
  spin_lock_irqsave(&x->wait.lock, flags);
  x->done += atomic_read(&kvm->online_vcpus) - 1;
  __wake_up_locked(&x->wait, TASK_NORMAL, 0);
  spin_unlock_irqrestore(&x->wait.lock, flags);
}

int nitro_vcpu_load(struct kvm_vcpu *vcpu)
{
  int cpu;

  if (mutex_lock_killable(&vcpu->mutex))
    return -EINTR;
  cpu = get_cpu();
  preempt_notifier_register(&vcpu->preempt_notifier);
  kvm_arch_vcpu_load(vcpu, cpu);
  put_cpu();
  return 0;
}

struct kvm* nitro_get_vm_by_creator(pid_t creator){
  struct kvm *rv;
  struct kvm *kvm;
  
  rv = NULL;
  
  spin_lock(&kvm_lock);
  list_for_each_entry(kvm,&vm_list,vm_list)
    if(kvm->mm->owner->pid == creator){
      rv = kvm;
      break;
    }
  spin_unlock(&kvm_lock);
  
  return rv;
}

void nitro_create_vm_hook(struct kvm *kvm){
  pid_t pid;
  
  //get current pid
  pid = pid_nr(get_task_pid(current, PIDTYPE_PID));
  printk(KERN_INFO "nitro: new VM created, creating process: %d\n", pid);
  
  //init nitro
  spin_lock_init(&kvm->nitro.nitro_lock);
  
  kvm->nitro.traps = 0;
  INIT_LIST_HEAD(&kvm->nitro.event_q);
  
  kvm->nitro.system_call_bm = NULL;
  kvm->nitro.system_call_max = 0;
  hash_init(kvm->nitro.system_call_rsp_ht);
  
  init_completion(&(kvm->nitro.k_wait_cv));
  sema_init(&(kvm->nitro.n_wait_sem),0);
}

void nitro_destroy_vm_hook(struct kvm *kvm){
  //struct nitro_event *e;
  
  //deinit nitro
  kvm->nitro.traps = 0;
  
  if(kvm->nitro.system_call_bm != NULL){
    kfree(kvm->nitro.system_call_bm);
    kvm->nitro.system_call_bm = NULL;
  }
  kvm->nitro.system_call_max = 0;
}

void nitro_create_vcpu_hook(struct kvm_vcpu *vcpu){
}

void nitro_destroy_vcpu_hook(struct kvm_vcpu *vcpu){
}

int nitro_iotcl_num_vms(void){
  struct kvm *kvm;
  int rv = 0;
  
  spin_lock(&kvm_lock);
  list_for_each_entry(kvm, &vm_list, vm_list)
    rv++;
  spin_unlock(&kvm_lock);
  
  return rv;
}

int nitro_iotcl_attach_vcpus(struct kvm *kvm, struct nitro_vcpus *nvcpus){
  int r,i;
  struct kvm_vcpu *v;
  
  mutex_lock(&kvm->lock);
  
  nvcpus->num_vcpus = atomic_read(&kvm->online_vcpus);
  if(unlikely(nvcpus->num_vcpus > NITRO_MAX_VCPUS)){
    goto error_out;
  }
  
  kvm_for_each_vcpu(r, v, kvm){
    nvcpus->ids[r] = v->vcpu_id;
    kvm_get_kvm(kvm);
    nvcpus->fds[r] = create_vcpu_fd(v);
    if(nvcpus->fds[r]<0){
      for(i=r;r>=0;i--){
	nvcpus->ids[r] = 0;
	nvcpus->fds[i] = 0;
	kvm_put_kvm(kvm);
      }
      goto error_out;
    }
  }
  
  mutex_unlock(&kvm->lock);
  return 0;
  
error_out:
  mutex_unlock(&kvm->lock);
  return -1;
}

int nitro_ioctl_get_event(struct kvm *kvm, void *argp){
  int rv;
  struct nitro_event *e;
  
  rv = down_interruptible(&(kvm->nitro.n_wait_sem));
  
  if (rv == 0){
    e = list_first_entry(&kvm->nitro.event_q,struct nitro_event,q);
    rv = e->event_id;
    if (copy_to_user(argp, &e->user_event_data, sizeof(union event_data)))
      rv = -EFAULT;
    list_del(&e->q);
    kfree(e);
  }
  
  return rv;
}

int nitro_ioctl_continue(struct kvm *kvm){
  
  //if no waiters
  if(completion_done(&(kvm->nitro.k_wait_cv)))
    return -1;
  
  nitro_complete_all(kvm,&(kvm->nitro.k_wait_cv));
  return 0;
}

inline int nitro_is_trap_set(struct kvm *kvm, uint32_t trap){
  return kvm->nitro.traps & trap;
}
