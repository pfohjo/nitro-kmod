#include "nitro_x86.h"

#include "x86.h"


#include <linux/kernel.h>
#include <linux/completion.h>

extern int kvm_set_msr_common(struct kvm_vcpu*, struct msr_data*);

int nitro_set_syscall_trap(struct kvm *kvm,unsigned long *bitmap,int system_call_max){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  
  printk(KERN_INFO "nitro: set syscall trap\n");
  
  kvm->nitro.system_call_bm = bitmap;
  kvm->nitro.system_call_max = system_call_max;
  
  kvm->nitro.traps |= NITRO_TRAP_SYSCALL;
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    //vcpu_load(vcpu);
    nitro_vcpu_load(vcpu);
    
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer & ~EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    
    init_completion(&kvm->nitro.k_wait_cv);
    
    vcpu_put(vcpu);
  }
  
  return 0;
}

int nitro_unset_syscall_trap(struct kvm *kvm){
  int i;
  struct kvm_vcpu *vcpu;
  u64 efer;
  struct msr_data msr_info;
  struct nitro_syscall_event_ht *ed;
  struct nitro_event *e, *n;
  
  printk(KERN_INFO "nitro: unset syscall trap\n");
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    //vcpu_load(vcpu);
    

    
    
    nitro_vcpu_load(vcpu);
    
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer | EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    

    
    vcpu_put(vcpu);
  }
  
  kvm->nitro.traps &= ~(NITRO_TRAP_SYSCALL);
  if(kvm->nitro.system_call_bm != NULL){
    kfree(kvm->nitro.system_call_bm);
    kvm->nitro.system_call_bm = NULL;
  }
  kvm->nitro.system_call_max = 0;
  
  
  hash_for_each(kvm->nitro.system_call_rsp_ht,i,ed,ht){
    kfree(ed);
  }
  
  
  if(!kvm->nitro.traps){
    list_for_each_entry_safe(e,n,&kvm->nitro.event_q,q){
      list_del(&e->q);
      kfree(e);
    }
    //if waiters, wake up
    complete_all(&(kvm->nitro.k_wait_cv));
  }

  return 0;
}

void nitro_wait(struct kvm *kvm){
  long rv;
  
  up(&(kvm->nitro.n_wait_sem));
  rv = wait_for_completion_interruptible_timeout(&(kvm->nitro.k_wait_cv),msecs_to_jiffies(30000));
  
  if (rv == 0)
    printk(KERN_INFO "nitro: %s: wait timed out\n",__FUNCTION__);
  else if (rv < 0)
    printk(KERN_INFO "nitro: %s: wait interrupted\n",__FUNCTION__);
  
  return;
}

int nitro_report_syscall(struct kvm *kvm, struct nitro_event *e){
  struct nitro_syscall_event_ht *ed;
  
  
  if(kvm->nitro.system_call_max > 0 && (e->syscall_event_nr > INT_MAX || e->syscall_event_nr > kvm->nitro.system_call_max || !test_bit((int)e->syscall_event_nr,kvm->nitro.system_call_bm)))
    return 0;
  
  ed = kzalloc(sizeof(struct nitro_syscall_event_ht),GFP_KERNEL);
  ed->rsp = e->syscall_event_rsp;
  ed->cr3 = e->syscall_event_cr3;
  nitro_hash_add(kvm,&ed,ed->rsp);

  nitro_wait(kvm);
  
  return 0;
}

int nitro_report_sysret(struct kvm *kvm, struct nitro_event *e){
  struct nitro_syscall_event_ht *ed;
  
  hash_for_each_possible(kvm->nitro.system_call_rsp_ht, ed, ht, e->syscall_event_rsp){
    if((ed->rsp == e->syscall_event_rsp) && (ed->cr3 == e->syscall_event_cr3)){
      hash_del(&ed->ht);
      kfree(ed);
      
      nitro_wait(kvm);
      break;
    }
  }
  
  return 0;
}

int nitro_report_event(struct kvm *kvm){
  int r, rv;
  struct nitro_event *e;
  
  r = 0;
  
  e = list_first_entry(&kvm->nitro.event_q,struct nitro_event,q);
  
  if(atomic_add_return(1,&e->num_waiters) < atomic_read(&kvm->online_vcpus)){
    printk(KERN_INFO "nitro: dumb waiting...\n");
    rv = wait_for_completion_interruptible_timeout(&(kvm->nitro.k_wait_cv),msecs_to_jiffies(30000));
  
    if (rv == 0)
      printk(KERN_INFO "nitro: %s: wait timed out\n",__FUNCTION__);
    else if (rv < 0)
      printk(KERN_INFO "nitro: %s: wait interrupted\n",__FUNCTION__);
    
    return 0;
  }
  
  switch(e->event_id){
    case KVM_NITRO_EVENT_ERROR:
      nitro_wait(kvm);
      break;
    case KVM_NITRO_EVENT_SYSCALL:
      r = nitro_report_syscall(kvm,e);
      break;
    case KVM_NITRO_EVENT_SYSRET:
      r = nitro_report_sysret(kvm,e);
      break;
    default:
      printk(KERN_INFO "nitro: %s: unknown event encountered (%d)\n",__FUNCTION__,e->event_id);
  }

  return r;
}

inline u64 nitro_get_efer(struct kvm_vcpu *vcpu){
  return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL) ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

