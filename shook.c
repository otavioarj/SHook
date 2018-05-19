/* 
 * Tested on kernel 4.9.18-1
 * It includes a dynamic symbol resolve for set_memory_rw
 */

#include <linux/module.h>   
#include <linux/syscalls.h> 
#include <linux/delay.h>    
#include <linux/kdev_t.h>
#include <linux/kallsyms.h> 
#include <linux/utsname.h>

#define CR0_WP 0x00010000   // Write-Protect Bit (CR0:16) amd64 


#ifndef _LP64
#error "Only supports x86_64 kernel<=> cpu!"
#endif


MODULE_LICENSE("GPL");

void **syscall_table;

// Prototypes (strict-prototypes)

asmlinkage long (*orig_sys_uname)(struct new_utsname *);
asmlinkage long hook_sys_uname(struct new_utsname *);
unsigned long **find_sys_call_table(void);
static int __init syscall_init(void);
static void __exit syscall_release(void);

/*Kernel >4.1 no longer exports set_memory_rw, here it's a fix :)*/
static int (*do_set_memory_rw)(unsigned long addr, int numpages) = NULL;


unsigned long **find_sys_call_table()
{
  
  unsigned long ptr;
  unsigned long *p;
  /* the sys_call_table can be found between the addresses of sys_close 
   * and loops_pre_jiffy. Look at /boot/System.map or /proc/kallsyms to 
   * see if it is the case for your kernel */
  for (ptr = (unsigned long)sys_close;
      ptr < (unsigned long)&loops_per_jiffy;
      ptr += sizeof(void *)) {
         
    p = (unsigned long *)ptr;

    /* Indexes such as __NR_close can be found in
     * /usr/include/x86_64-linux-gnu/asm/unistd{,_64}.h
     * syscalls function can be found in
     * /usr/src/`uname -r`/include/linux/syscalls.h */
    if (p[__NR_close] == (unsigned long)sys_close) {
      /* the address of the sys_close function is equal to the one found
       * in the sys_call_table */
      printk(KERN_DEBUG "[HOOK] Found the sys_call_table!!!\n");
      return (unsigned long **)p;
    }
  }
  
  return NULL;
}


asmlinkage long hook_sys_uname(struct new_utsname *name) {
    orig_sys_uname(name);      
    strncpy(name->sysname,"Hooked, yep :)", 14);
    return 0;
}


static int __init syscall_init(void)
{
  int ret;
  unsigned long addr;
  unsigned long cr0;
  
  /* get the sys_call_table address */
  syscall_table = (void **)find_sys_call_table();

  if (!syscall_table) {
    printk(KERN_DEBUG "[HOOK] Cannot find the system call address\n"); 
    return -1;
  }
  /* get the value of the CR0 register */
  cr0 = read_cr0();
  /* disable the Write-Protect bit */
  write_cr0(cr0 & ~CR0_WP);
  /* set the memory covered by the sys_call_table writable */
  addr = (unsigned long)syscall_table;
  
  
  do_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
	if (do_set_memory_rw == NULL) 
	{
		printk(KERN_DEBUG "[HOOK] Symbol not found: 'set_memory_rw'\n");
		return -EINVAL;
	}
  
  
  ret = do_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);
  if(ret) {
    printk(KERN_DEBUG 
           "[HOOK] Cannot set the memory to rw (%d) at addr %16lX\n",
           ret, PAGE_ALIGN(addr) - PAGE_SIZE);
  } else {
    printk(KERN_DEBUG "[HOOK] 3 pages set to rw\n");
  }

   
  /* Hooking*/
  orig_sys_uname = syscall_table[__NR_uname];
  syscall_table[__NR_uname] = hook_sys_uname;
  
  /* restore the Write-Protect bit */
  write_cr0(cr0);
  return 0;
}


static void __exit syscall_release(void)
{
  unsigned long cr0;
  /* get the value of the CR0 register */
  cr0 = read_cr0();
  /* disable the Write-Protect bit */
  write_cr0(cr0 & ~CR0_WP);  
  syscall_table[__NR_uname] = orig_sys_uname;
  /* restore the Write-Protect bit */
  write_cr0(cr0);
  printk(KERN_DEBUG "[HOOK] released module\n");
}

module_init(syscall_init);
module_exit(syscall_release);
