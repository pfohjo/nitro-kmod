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
#include <linux/sched.h>

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
/*
void nitro_resched_task(struct task_struct *p){
  int cpu;

  //lockdep_assert_held(&task_rq(p)->lock);

  if (test_tsk_need_resched(p))
    return;

  set_tsk_need_resched(p);

  cpu = task_cpu(p);
  if (cpu == smp_processor_id()) {
    set_preempt_need_resched();
    return;
  }

  // NEED_RESCHED must be visible before we test polling 
  smp_mb();
  if (!tsk_is_polling(p))
    smp_send_reschedule(cpu);
}
*/

void nitro_pause(struct kvm_vcpu *vcpu){
  int i;
  struct kvm_vcpu *cur;
  struct task_struct *task;
  
  kvm_for_each_vcpu(i, cur, vcpu->kvm){
    if(cur != vcpu){
      
      /*
      nitro_vcpu_load(cur);
      
      task = get_pid_task(cur->pid,PIDTYPE_PID);
      printk(KERN_INFO "nitro: %s: vcpu %d pausing vcpu %d with current state %ld\n",__FUNCTION__,vcpu->vcpu_id,cur->vcpu_id,task->state);
      
      //write_lock(&tasklist_lock);
      // __set_task_state(task,TASK_INTERRUPTIBLE);
      set_task_state(task,TASK_UNINTERRUPTIBLE);
      //write_unlock(&tasklist_lock);
      
      
      //look at kvm_vcpu_kick and kvm_resched in kvm_main.c
      nitro_resched_task(task);
      
      vcpu_put(cur);
      */
      
      task = get_pid_task(cur->pid,PIDTYPE_PID);
      printk(KERN_INFO "nitro: %s: vcpu %d pausing vcpu %d with current state %ld\n",__FUNCTION__,vcpu->vcpu_id,cur->vcpu_id,task->state);
      
      sigaddset(&task->pending.signal, SIGSTOP);
      set_tsk_thread_flag(task, TIF_SIGPENDING);
//      if (!wake_up_state(task, TASK_WAKEKILL | TASK_INTERRUPTIBLE))
//	kick_process(task);
      
    }
  }

  return;
}

void nitro_unpause(struct kvm_vcpu *vcpu){
  int i;
  struct kvm_vcpu *cur;
  struct task_struct *task;
  
  kvm_for_each_vcpu(i, cur, vcpu->kvm){
    if(cur != vcpu){
      /*
      task = get_pid_task(cur->pid,PIDTYPE_PID);
      printk(KERN_INFO "nitro: %s: vcpu %d waking up vcpu %d with current state %ld\n",__FUNCTION__,vcpu->vcpu_id,cur->vcpu_id,task->state);
      wake_up_process(task);
      */
      
      task = get_pid_task(cur->pid,PIDTYPE_PID);
      printk(KERN_INFO "nitro: %s: vcpu %d waking up vcpu %d with current state %ld\n",__FUNCTION__,vcpu->vcpu_id,cur->vcpu_id,task->state);
      sigaddset(&task->pending.signal, SIGCONT);
      set_tsk_thread_flag(task, TIF_SIGPENDING);
//    if (!wake_up_state(task, TASK_WAKEKILL | TASK_INTERRUPTIBLE))
//	kick_process(task);
      
    }
  }

  
  return;
}

int nitro_wait_for_completion(struct nitro_completion *completion){
  int rv;
  
  DECLARE_WAITQUEUE(wait, current);
  
  might_sleep();
  spin_lock_irq(&completion->wait.lock);
 
  rv = 0;
  
  //printk(KERN_INFO "nitro: %s: tid %d entering cv with waiters=%d\n",__FUNCTION__,current->tgid,completion->waiters);
  
  completion->waiters++;
  __add_wait_queue_tail_exclusive(&completion->wait, &wait);
  do {
    if (signal_pending_state(TASK_INTERRUPTIBLE, current)) {
      rv = -ERESTARTSYS;
      break;
    }
    __set_current_state(TASK_INTERRUPTIBLE);
    spin_unlock_irq(&completion->wait.lock);
    schedule_timeout(MAX_SCHEDULE_TIMEOUT);
    spin_lock_irq(&completion->wait.lock);
  } while (!completion->done);
  __remove_wait_queue(&completion->wait, &wait);
  
  if (completion->done)
    completion->done--;
  
  if (completion->waiters)
    completion->waiters--;
  
  //printk(KERN_INFO "nitro: %s: tid %d leaving cv with waiters=%d\n",__FUNCTION__,current->tgid,completion->waiters);
  spin_unlock_irq(&completion->wait.lock);
  

  return rv;
}

int nitro_not_last_wait_for_completion(struct nitro_completion *completion, int compare){
  long rv;
  
  DECLARE_WAITQUEUE(wait, current);
  
  might_sleep();
  spin_lock_irq(&completion->wait.lock);
  
  //printk(KERN_INFO "nitro: %s: checking if last vcpu with waiters=%d and compare=%d\n",__FUNCTION__,completion->waiters,compare);
  if(completion->waiters >= compare-1){
    //printk(KERN_INFO "nitro: %s: im the last\n",__FUNCTION__);
    spin_unlock_irq(&completion->wait.lock);
    return 0;
  }
  
  rv = 1;
  
  //printk(KERN_INFO "nitro: %s: tid %d entering cv with waiters=%d\n",__FUNCTION__,current->tgid,completion->waiters);
  
  completion->waiters++;
  __add_wait_queue_tail_exclusive(&completion->wait, &wait);
  do {
    if (signal_pending_state(TASK_INTERRUPTIBLE, current)) {
      rv = -ERESTARTSYS;
      break;
    }
    __set_current_state(TASK_INTERRUPTIBLE);
    spin_unlock_irq(&completion->wait.lock);
    schedule_timeout(MAX_SCHEDULE_TIMEOUT);
    spin_lock_irq(&completion->wait.lock);
  } while (!completion->done);
  __remove_wait_queue(&completion->wait, &wait);
  
  if (completion->done)
    completion->done--;
  
  if (completion->waiters)
    completion->waiters--;
  
  //printk(KERN_INFO "nitro: %s: tid %d leaving cv with waiters=%d\n",__FUNCTION__,current->tgid,completion->waiters);
  spin_unlock_irq(&completion->wait.lock);

  return rv;
}

void nitro_complete_all(struct nitro_completion *completion){
  unsigned long flags;
  
  spin_lock_irqsave(&completion->wait.lock, flags);
  completion->done =  completion->waiters;
  __wake_up_locked(&completion->wait, TASK_NORMAL, 0);
  spin_unlock_irqrestore(&completion->wait.lock, flags);
}

bool nitro_completion_num_waiters(struct nitro_completion *completion){
  unsigned long flags;
  int ret = 0;
  
  spin_lock_irqsave(&completion->wait.lock, flags);
  ret = completion->waiters;
  spin_unlock_irqrestore(&completion->wait.lock, flags);
  return ret;
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
  mutex_init(&kvm->nitro.nitro_report_lock);
  
  kvm->nitro.traps = 0;
  INIT_LIST_HEAD(&kvm->nitro.event_q);
  
  kvm->nitro.system_call_bm = NULL;
  kvm->nitro.system_call_max = 0;
  hash_init(kvm->nitro.system_call_rsp_ht);
  
  sema_init(&(kvm->nitro.n_wait_sem),0);
  init_completion(&kvm->nitro.k_wait_cv);
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
  //vcpu->nitro.wait = __WAIT_QUEUE_HEAD_INITIALIZER(vcpu->nitro.wait);
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
    spin_lock(&kvm->nitro.nitro_lock);
    e = list_first_entry(&kvm->nitro.event_q,struct nitro_event,q);
    list_del(&e->q);
    spin_unlock(&kvm->nitro.nitro_lock);
    rv = e->event_id;
    if (copy_to_user(argp, &e->user_event_data, sizeof(union event_data)))
      rv = -EFAULT;
    kfree(e);
  }
  
  return rv;
}

int nitro_ioctl_continue(struct kvm *kvm){
  
  //if no waiters
  //if(completion_done(&kvm->nitro.k_wait_cv))
  //  return -1;
  
  complete(&kvm->nitro.k_wait_cv);
  return 0;
}

inline int nitro_is_trap_set(struct kvm *kvm, uint32_t trap){
  return kvm->nitro.traps & trap;
}
