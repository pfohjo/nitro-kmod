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
  
  struct task_struct *t;
  
  printk(KERN_INFO "nitro: set syscall trap, we have %d threads\n",get_nr_threads(current));
  
  kvm->nitro.system_call_bm = bitmap;
  kvm->nitro.system_call_max = system_call_max;
    
  //init completion
  reinit_completion(&kvm->nitro.k_wait_cv);
  
  kvm->nitro.traps |= NITRO_TRAP_SYSCALL;
  
  kvm_for_each_vcpu(i, vcpu, kvm){
    //vcpu_load(vcpu);
    nitro_vcpu_load(vcpu);
    
    kvm_get_msr_common(vcpu, MSR_EFER, &efer);
    msr_info.index = MSR_EFER;
    msr_info.data = efer & ~EFER_SCE;
    msr_info.host_initiated = true;
    kvm_set_msr_common(vcpu, &msr_info);
    
    vcpu_put(vcpu);
    
    
    if((t = get_pid_task(vcpu->pid,PIDTYPE_PID)))
      printk(KERN_INFO "vcpu %d, PIDTYPE_PID: task.pid = %d, task.tgid = %d\n",vcpu->vcpu_id,t->pid,t->tgid);
    else
      printk(KERN_INFO "vcpu %d, PIDTYPE_PID: NULL\n",vcpu->vcpu_id);
    
    if((t = get_pid_task(vcpu->pid,PIDTYPE_PGID)))
      printk(KERN_INFO "vcpu %d, PIDTYPE_PGID: task.pid = %d, task.tgid = %d\n",vcpu->vcpu_id,t->pid,t->tgid);
    else
      printk(KERN_INFO "vcpu %d, PIDTYPE_PGID: NULL\n",vcpu->vcpu_id);
    
    if((t = get_pid_task(vcpu->pid,PIDTYPE_SID)))
      printk(KERN_INFO "vcpu %d, PIDTYPE_SID: task.pid = %d, task.tgid = %d\n",vcpu->vcpu_id,t->pid,t->tgid);
    else
      printk(KERN_INFO "vcpu %d, PIDTYPE_SID: NULL\n",vcpu->vcpu_id);
    
    if((t = get_pid_task(vcpu->pid,PIDTYPE_MAX)))
      printk(KERN_INFO "vcpu %d, PIDTYPE_MAX: task.pid = %d, task.tgid = %d\n",vcpu->vcpu_id,t->pid,t->tgid);
    else
      printk(KERN_INFO "vcpu %d, PIDTYPE_MAX: NULL\n",vcpu->vcpu_id);
    
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
    complete_all(&kvm->nitro.k_wait_cv);
  }

  return 0;
}

//this function assumes only last vcpu will enter once all others have been put to sleep in nitro_report_event
int nitro_wait(struct kvm_vcpu *vcpu){
  int rv = 0;
  struct kvm *kvm;
  
  kvm = vcpu->kvm;
  
  up(&(kvm->nitro.n_wait_sem));
  //printk(KERN_INFO "nitro: %s: woke up userland, sleeping...\n",__FUNCTION__);
  spin_unlock(&kvm->nitro.nitro_lock);
  nitro_pause(vcpu);
  if(wait_for_completion_interruptible(&kvm->nitro.k_wait_cv)){
    printk(KERN_INFO "nitro: %s: wait interrupted\n",__FUNCTION__);
    rv = -1;
  }
  nitro_unpause(vcpu);
  spin_lock(&kvm->nitro.nitro_lock);
  //printk(KERN_INFO "nitro: %s: woke up...\n",__FUNCTION__);
  
  return rv;
}

//this function assumes only last vcpu will enter once all others have been put to sleep in nitro_report_event
int nitro_report_syscall(struct kvm_vcpu *vcpu, struct nitro_event *e){
  struct nitro_syscall_event_ht *ed;
  struct kvm *kvm;
  
  kvm = vcpu->kvm;
  
  if(kvm->nitro.system_call_max > 0 && (e->syscall_event_nr > INT_MAX || e->syscall_event_nr > kvm->nitro.system_call_max || !test_bit((int)e->syscall_event_nr,kvm->nitro.system_call_bm))){
    list_del(&e->q);
    kfree(e);
    return 0;
  }
  
  ed = kzalloc(sizeof(struct nitro_syscall_event_ht),GFP_KERNEL);
  ed->rsp = e->syscall_event_rsp;
  ed->cr3 = e->syscall_event_cr3;
  nitro_hash_add(kvm,&ed,ed->rsp);

  return nitro_wait(vcpu);
}

//this function assumes only last vcpu will enter once all others have been put to sleep in nitro_report_event
int nitro_report_sysret(struct kvm_vcpu *vcpu, struct nitro_event *e){
  struct nitro_syscall_event_ht *ed;
  struct hlist_node *tmp;
  
  hash_for_each_possible_safe(vcpu->kvm->nitro.system_call_rsp_ht, ed, tmp, ht, e->syscall_event_rsp){
    if((ed->rsp == e->syscall_event_rsp) && (ed->cr3 == e->syscall_event_cr3)){
      hash_del(&ed->ht);
      kfree(ed);
      return nitro_wait(vcpu);
    }
  }
  
  list_del(&e->q);
  kfree(e);
  
  return 0;
}

int nitro_report_event(struct kvm_vcpu *vcpu){
  int r, le;
  struct nitro_event *e;
  struct kvm *kvm;
  
  r = 0;
  kvm = vcpu->kvm;
  
  if(!mutex_trylock(&kvm->nitro.nitro_report_lock))
    return 0;
  
  spin_lock(&kvm->nitro.nitro_lock);
  le = list_empty(&kvm->nitro.event_q);
  
  if(le){
    spin_unlock(&kvm->nitro.nitro_lock);
    mutex_unlock(&kvm->nitro.nitro_report_lock);
    return 0;
  }
  
  
  
  
  do{
    
    e = list_first_entry(&kvm->nitro.event_q,struct nitro_event,q);
    //printk(KERN_INFO "nitro: %s: reporting event %u\n",__FUNCTION__,e->event_id);
    switch(e->event_id){
      case KVM_NITRO_EVENT_ERROR:
	r = nitro_wait(vcpu);
	break;
      case KVM_NITRO_EVENT_SYSCALL:
	r = nitro_report_syscall(vcpu,e);
	break;
      case KVM_NITRO_EVENT_SYSRET:
	r = nitro_report_sysret(vcpu,e);
	break;
      default:
	printk(KERN_INFO "nitro: %s: unknown event encountered (%d)\n",__FUNCTION__,e->event_id);
	list_del(&e->q);
	kfree(e);
	break;
    }
    
    if(r)
      break;
    
    le = list_empty(&kvm->nitro.event_q);
    
  }while(!le);
  spin_unlock(&kvm->nitro.nitro_lock);
  mutex_unlock(&kvm->nitro.nitro_report_lock);
  return r;
}

inline u64 nitro_get_efer(struct kvm_vcpu *vcpu){
  return nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL) ? (vcpu->arch.efer | EFER_SCE) : vcpu->arch.efer;
}

