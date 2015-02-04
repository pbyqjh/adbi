/* 
 * hijack.c - force a process to load a library
 *
 *  ARM / Android version by:
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *	(c) 2012,2013
 *
 *
 *  original x86 version by:
 *  Copyright (C) 2002 Victor Zandy <zandy[at]cs.wisc.edu>
 *
 *  License: LGPL 2.1
 *
 */
 
#define _XOPEN_SOURCE 500  /* include pread,pwrite */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>       
#include <sys/mman.h>

int debug = 0;
int zygote = 0;
int nomprotect = 0;
unsigned int stack_start;
unsigned int stack_end;

/* memory map for libraries */
#define MAX_NAME_LEN 256
#define MEMORY_ONLY  "[memory]"
struct mm {
	char name[MAX_NAME_LEN];
	unsigned long start, end;
};

typedef struct symtab *symtab_t;
struct symlist {
	Elf32_Sym *sym;       /* symbols */
	char *str;            /* symbol strings */
	unsigned num;         /* number of symbols */
};
struct symtab {
	struct symlist *st;    /* "static" symbols */
	struct symlist *dyn;   /* dynamic symbols */
};

static void * 
xmalloc(size_t size)
{
	void *p;
	p = malloc(size);
	if (!p) {
		printf("Out of memory\n");
		exit(1);
	}
	return p;
}
/*
#int fd so文件对应的fd
#Elf32_Shdr *symh 符号表起始地址，后面是一项一项的符号表
#Elf32_Shdr *strh 符号表对应的字符串表的其实地址，每一项符号表的符号名称代表的是名称字符串在该表中的偏移位置
*/
static struct symlist *
get_syms(int fd, Elf32_Shdr *symh, Elf32_Shdr *strh)
{
	struct symlist *sl, *ret;
	int rv;

	ret = NULL;
	sl = (struct symlist *) xmalloc(sizeof(struct symlist));
	sl->str = NULL;
	sl->sym = NULL;

	/* sanity */
	if (symh->sh_size % sizeof(Elf32_Sym)) { 
		printf("elf_error\n");
		goto out;
	}

	/* symbol table */
	sl->num = symh->sh_size / sizeof(Elf32_Sym);
	sl->sym = (Elf32_Sym *) xmalloc(symh->sh_size);
	rv = pread(fd, sl->sym, symh->sh_size, symh->sh_offset);
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != symh->sh_size) {
		printf("elf error\n");
		goto out;
	}

	/* string table */
	sl->str = (char *) xmalloc(strh->sh_size);
	rv = pread(fd, sl->str, strh->sh_size, strh->sh_offset);
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != strh->sh_size) {
		printf("elf error");
		goto out;
	}

	ret = sl;
out:
	return ret;
}

/*
从fd中读取so，把so的符号表，以及符号表对应的字符串表信息保存在一个symtab_t结构体中方便查找函数
*/
static int
do_load(int fd, symtab_t symtab)
{
	int rv;
	size_t size;
	Elf32_Ehdr ehdr;//elf文件的文件头，一定位于elf文件的开头
	Elf32_Shdr *shdr = NULL, *p;
	Elf32_Shdr *dynsymh, *dynstrh;
	Elf32_Shdr *symh, *strh;
	char *shstrtab = NULL;
	int i;
	int ret = -1;
	
	/* elf header */
	rv = read(fd, &ehdr, sizeof(ehdr));
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != sizeof(ehdr)) {
		printf("elf error\n");
		goto out;
	}
	//判断文件头中保存的魔数,ELFMAG，一共4个字节，对于正常的ELF文件来说，这个结构体是固定的
	if (strncmp(ELFMAG, ehdr.e_ident, SELFMAG)) { /* sanity */
		printf("not an elf\n");
		goto out;
	}
	if (sizeof(Elf32_Shdr) != ehdr.e_shentsize) { /* sanity */
		printf("elf error\n");
		goto out;
	}

	/* section header table */
	size = ehdr.e_shentsize * ehdr.e_shnum;
	shdr = (Elf32_Shdr *) xmalloc(size);
	rv = pread(fd, shdr, size, ehdr.e_shoff);//ehdr.e_shoff表示的是section_header_table在文件中的偏移
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != size) {
		printf("elf error");
		goto out;
	}
	
	/* section header string table */
	size = shdr[ehdr.e_shstrndx].sh_size;
	/*
	ehdr.e_shstrndx表示包含节名称的字符串是第几个节，这里shdr[ehdr.e_shstrndx]应该是包含节名称的节,是一个Elf32_Shdr类型的指针
	定义如下
	typedef struct {
        elf32_Word      sh_name;//节的名称，实际上是段名字符串在.shstrtab段中的偏移,而ehdr.e_shstrndx是shstrtab在所有段表中的序号
        Elf32_Word      sh_type;
        Elf32_Word      sh_flags;
        Elf32_Addr      sh_addr;//如果节被加载在内存中，代表在内存中的起始位置
        Elf32_Off       sh_offset;//文件开头到节的第一个字节的偏移
        Elf32_Word      sh_size;//节的大小
        Elf32_Word      sh_link;
        Elf32_Word      sh_info;
        Elf32_Word      sh_addralign;
        Elf32_Word      sh_entsize;
        } Elf32_Shdr;
	*/
	shstrtab = (char *) xmalloc(size);
	rv = pread(fd, shstrtab, size, shdr[ehdr.e_shstrndx].sh_offset);//从文件中读取包含节名称的节
	if (0 > rv) {
		//perror("read");
		goto out;
	}
	if (rv != size) {
		printf("elf error\n");
		goto out;
	}

	/* symbol table headers */
	symh = dynsymh = NULL;
	strh = dynstrh = NULL;
	for (i = 0, p = shdr; i < ehdr.e_shnum; i++, p++)//ehdr.e_shnum代表的是所有的节的个数
		if (SHT_SYMTAB == p->sh_type) {//符号表
			if (symh) {
				printf("too many symbol tables\n");
				goto out;
			}
			symh = p;
		} else if (SHT_DYNSYM == p->sh_type) {//动态链接符号表
			if (dynsymh) {
				printf("too many symbol tables\n");
				goto out;
			}
			dynsymh = p;
		} else if (SHT_STRTAB == p->sh_type  
			   && !strncmp(shstrtab+p->sh_name, ".strtab", 7)) {//字符串表
			if (strh) {
				printf("too many string tables\n");
				goto out;
			}
			strh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".dynstr", 7)) {
			if (dynstrh) {
				printf("too many string tables\n");
				goto out;
			}
			dynstrh = p;
		}
	/* sanity checks */
	if ((!dynsymh && dynstrh) || (dynsymh && !dynstrh)) {
		printf("bad dynamic symbol table");
		goto out;
	}
	if ((!symh && strh) || (symh && !strh)) {
		printf("bad symbol table");
		goto out;
	}
	if (!dynsymh && !symh) {
		printf("no symbol table");
		goto out;
	}

	/* symbol tables */
	if (dynsymh)
		symtab->dyn = get_syms(fd, dynsymh, dynstrh);
	if (symh)
		symtab->st = get_syms(fd, symh, strh);
	ret = 0;
out:
	free(shstrtab);
	free(shdr);
	return ret;
}
/*
读取名为filename的so，把so的符号表，以及符号表对应的字符串表信息保存在一个symtab_t结构体中方便查找函数
*/
static symtab_t
load_symtab(char *filename)
{
	int fd;
	symtab_t symtab;

	symtab = (symtab_t) xmalloc(sizeof(*symtab));
	memset(symtab, 0, sizeof(*symtab));

	fd = open(filename, O_RDONLY);
	if (0 > fd) {
		//perror("open");
		return NULL;
	}
	if (0 > do_load(fd, symtab)) {
		printf("Error ELF parsing %s\n", filename);
		free(symtab);
		symtab = NULL;
	}
	close(fd);
	return symtab;
}


static int
load_memmap(pid_t pid, struct mm *mm, int *nmmp) // 根据pid从/proc/pid/map读取进程内存映射信息保存起来
{
	char raw[80000]; // this depends on the number of libraries an executable uses
	char name[MAX_NAME_LEN];
	char *p;
	unsigned long start, end;
	struct mm *m;
	int nmm = 0;
	int fd, rv;
	int i;

	sprintf(raw, "/proc/%d/maps", pid);
	fd = open(raw, O_RDONLY);
	if (0 > fd) {
		printf("Can't open %s for reading\n", raw);
		return -1;
	}

	/* Zero to ensure data is null terminated */
	memset(raw, 0, sizeof(raw));

	p = raw;
	while (1) {
		rv = read(fd, p, sizeof(raw)-(p-raw));
		if (0 > rv) {
			//perror("read");
			return -1;
		}
		if (0 == rv)
			break;
		p += rv;
		if (p-raw >= sizeof(raw)) {
			printf("Too many memory mapping\n");
			return -1;
		}
	}
	close(fd);

	p = strtok(raw, "\n");
	m = mm;
	while (p) {
		/* parse current map line */
		rv = sscanf(p, "%08lx-%08lx %*s %*s %*s %*s %s\n",
			    &start, &end, name);

		p = strtok(NULL, "\n");
/*
正常的map文件格式
40096000-40098000 r-xp 00000000 b3:16 109        /system/bin/app_process
40098000-40099000 r--p 00001000 b3:16 109        /system/bin/app_process
40099000-4009a000 rw-p 00000000 00:00 0 
4009a000-400a9000 r-xp 00000000 b3:16 176        /system/bin/linker
400a9000-400aa000 r--p 0000e000 b3:16 176        /system/bin/linker
400aa000-400ab000 rw-p 0000f000 b3:16 176        /system/bin/linker
400ab000-400ae000 rw-p 00000000 00:00 0 
400ae000-400b0000 r--p 00000000 00:00 0 
400b0000-400b9000 r-xp 00000000 b3:16 855        /system/lib/libcutils.so
400b9000-400ba000 r--p 00008000 b3:16 855        /system/lib/libcutils.so
400ba000-400bb000 rw-p 00009000 b3:16 855        /system/lib/libcutils.so
400bb000-400be000 r-xp 00000000 b3:16 955        /system/lib/liblog.so
400be000-400bf000 r--p 00002000 b3:16 955        /system/lib/liblog.so
400bf000-400c0000 rw-p 00003000 b3:16 955        /system/lib/liblog.so
400c0000-40107000 r-xp 00000000 b3:16 832        /system/lib/libc.so
40107000-40108000 ---p 00000000 00:00 0 

只匹配到2个参数，说明最后名称为空，name统一赋值为MEMORT_ONLY

名称为空的映射段不需要进行合并，直接continue进行下一行的处理
*/
		if (rv == 2) {
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, MEMORY_ONLY);
			continue;
		}

		if (strstr(name, "stack") != 0) {
			stack_start = start;
			stack_end = end;
		}
/*
代码走到这里说明是类似这种的映射
400b0000-400b9000 r-xp 00000000 b3:16 855        /system/lib/libcutils.so
400b9000-400ba000 r--p 00008000 b3:16 855        /system/lib/libcutils.so
400ba000-400bb000 rw-p 00009000 b3:16 855        /system/lib/libcutils.so
可能是对同一个so的映射，因此需要在mm中进行寻找，如果之前有相同那么的映射信息，进行合并，否则新建一个
*/
		/* search backward for other mapping with same name */
		for (i = nmm-1; i >= 0; i--) {
			m = &mm[i];
			if (!strcmp(m->name, name))
				break;
		}

		if (i >= 0) {
			if (start < m->start)
				m->start = start;
			if (end > m->end)
				m->end = end;
		} else {
			/* new entry */
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, name);
		}
	}

	*nmmp = nmm;
	return 0;
}

/* Find libc in MM, storing no more than LEN-1 chars of
   its name in NAME and set START to its starting
   address.  If libc cannot be found return -1 and
   leave NAME and START untouched.  Otherwise return 0
   and null-terminated NAME. */
   
/*
专门用来寻找libc在内存中的映射信息，传入mm的地址和映射信息的个数nmm
name是查抄到的so的名称，这里libc可能是下面的名称'libc.so' or 'libc-[0-9]'
start是libc在内存中的映射地址
*/
static int
find_libc(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strncmp("libc", p, 4))
			continue;
		p += 4;

		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

/*
和find_libc类似，在mm中寻找linker，name是名称，start是地址
*/
static int
find_linker_mem(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		//printf("name = %s\n", m->name);
		//printf("start = %x\n", m->start);
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strncmp("linker", p, 6))
			continue;
		break; // <--- hack
		p += 4;

		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

static int
lookup2(struct symlist *sl, unsigned char type,
	char *name, unsigned long *val)
{
	Elf32_Sym *p;
	int len;
	int i;

	len = strlen(name);
	for (i = 0, p = sl->sym; i < sl->num; i++, p++) {
		//printf("name: %s %x\n", sl->str+p->st_name, p->st_value);
		if (!strncmp(sl->str+p->st_name, name, len)
		    && ELF32_ST_TYPE(p->st_info) == type) {
			//if (p->st_value != 0) {
			*val = p->st_value;
			return 0;
			//}
		}
	}
	return -1;
}

static int
lookup_sym(symtab_t s, unsigned char type,
	   char *name, unsigned long *val)
{
	if (s->dyn && !lookup2(s->dyn, type, name, val))
		return 0;
	if (s->st && !lookup2(s->st, type, name, val))
		return 0;
	return -1;
}

static int
lookup_func_sym(symtab_t s, char *name, unsigned long *val)
{
	return lookup_sym(s, STT_FUNC, name, val);
}
/*
#pid_t pid 需要查找函数地址的进程pid
#char *name 需要查找的函数的名称
#unsigned long *addr用来返回查找到的函数的地址

1首先通过load_memmap从proc文件下获取对应pid进程的内存映射情况
2通过findlibc找出对应进程中libc加载到内存的中的地址
3调用load_symtab读取so获取so的符号表信息
4lookup_func_sym通过符号表信息获取要查找的函数相对于libc的偏移地址
5计算出需要查找的函数在内存中的位置
*/
static int
find_name(pid_t pid, char *name, unsigned long *addr)
{
	struct mm mm[1000];
	unsigned long libcaddr;
	int nmm;
	char libc[256];
	symtab_t s;

	if (0 > load_memmap(pid, mm, &nmm)) {
		printf("cannot read memory map\n");
		return -1;
	}
	if (0 > find_libc(libc, sizeof(libc), &libcaddr, mm, nmm)) {
		printf("cannot find libc\n");
		return -1;
	}
	s = load_symtab(libc);
	if (!s) {
		printf("cannot read symbol table\n");
		return -1;
	}
	if (0 > lookup_func_sym(s, name, addr)) {
		printf("cannot find %s\n", name);
		return -1;
	}
	*addr += libcaddr;
	return 0;
}
/*
查找linker在对应进程的地址空间中的地址
*/
static int find_linker(pid_t pid, unsigned long *addr)
{
	struct mm mm[1000];
	unsigned long libcaddr;
	int nmm;
	char libc[256];
	symtab_t s;

	if (0 > load_memmap(pid, mm, &nmm)) {
		printf("cannot read memory map\n");
		return -1;
	}
	if (0 > find_linker_mem(libc, sizeof(libc), &libcaddr, mm, nmm)) {
		printf("cannot find libc\n");
		return -1;
	}
	
	*addr = libcaddr;
	
	return 1;
}

/* Write NLONG 4 byte words from BUF into PID starting
   at address POS.  Calling process must be attached to PID. */
static int
write_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;
	//PTRACE_POKETEXT往目标进程的中写如一个字节
	for (p = buf, i = 0; i < nlong; p++, i++)
		if (0 > ptrace(PTRACE_POKETEXT, pid, (void *)(pos+(i*4)), (void *)*p))
			return -1;
	return 0;
}

static int
read_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++)
		if ((*p = ptrace(PTRACE_PEEKTEXT, pid, (void *)(pos+(i*4)), (void *)*p)) < 0)
			return -1;
	return 0;
}

unsigned int sc_old[] = {
// libname
0xe59f0030, // ldr     r0, [pc, #48] | addr of "libname" in r0
0xe3a01000, // mov     r1, #0        | r1 = 0 (flags=0)
0xe1a0e00f, // mov     lr, pc        | populate lr
0xe59ff028, // ldr     pc, [pc, #40] | call dlopen()
0xe59fd01c, // ldr     sp, [pc, #28] | fix sp
0xe59f0008, // ldr     r0, [pc, #12] | fix r0
0xe59f1008, // ldr     r1, [pc, #12] | fix r1
0xe59fe008, // ldr     lr, [pc, #12] | fix lr
0xe59ff008, // ldr     pc, [pc, #12] | fix pc (continue process)
0xe1a00000, // nop (mov r0,r0)       | r0
0xe1a00000, // nop (mov r0,r0)       | r1
0xe1a00000, // nop (mov r0,r0)       | lr
0xe1a00000, // nop (mov r0,r0)       | pc
0xe1a00000, // nop (mov r0,r0)       | sp
0xe1a00000, // nop (mov r0,r0)       | addr of libname
0xe1a00000  // nop (mov r0,r0)       | dlopen address
};

unsigned int sc[] = {
0xe59f0040, //        ldr     r0, [pc, #64]   ; 48 <.text+0x48> 把libname的addr赋值给ro寄存器
0xe3a01000, //        mov     r1, #0  ; 0x0                     0赋值给r1寄存器
0xe1a0e00f, //        mov     lr, pc				pc寄存器的值赋值给lr寄存器，函数返回后会继续执行ldr pc, [pc, #56]
0xe59ff038, //        ldr     pc, [pc, #56]   ; 4c <.text+0x4c> 把pc+56地址的内容(dlopen的地址)赋值给pc寄存器，就是执行dlopen(libname,0)
0xe59fd02c, //        ldr     sp, [pc, #44]   ; 44 <.text+0x44> 调用dlopen已经返回，开始还原寄存器
0xe59f0010, //        ldr     r0, [pc, #20]   ; 30 <.text+0x30>
0xe59f1010, //        ldr     r1, [pc, #20]   ; 34 <.text+0x34>
0xe59f2010, //        ldr     r2, [pc, #20]   ; 38 <.text+0x38>
0xe59f3010, //        ldr     r3, [pc, #20]   ; 3c <.text+0x3c>
0xe59fe010, //        ldr     lr, [pc, #20]   ; 40 <.text+0x40>
0xe59ff010, //        ldr     pc, [pc, #20]   ; 44 <.text+0x44>
0xe1a00000, //        nop                     r0                        sc[11]
0xe1a00000, //        nop                     r1 
0xe1a00000, //        nop                     r2 
0xe1a00000, //        nop                     r3 
0xe1a00000, //        nop                     lr 
0xe1a00000, //        nop                     pc
0xe1a00000, //        nop                     sp
0xe1a00000, //        nop                     addr of libname
0xe1a00000, //        nop                     dlopenaddr
};

struct pt_regs2 {
         long uregs[18];
};

#define ARM_cpsr        uregs[16]
#define ARM_pc          uregs[15]
#define ARM_lr          uregs[14]
#define ARM_sp          uregs[13]
#define ARM_ip          uregs[12]
#define ARM_fp          uregs[11]
#define ARM_r10         uregs[10]
#define ARM_r9          uregs[9]
#define ARM_r8          uregs[8]
#define ARM_r7          uregs[7]
#define ARM_r6          uregs[6]
#define ARM_r5          uregs[5]
#define ARM_r4          uregs[4]
#define ARM_r3          uregs[3]
#define ARM_r2          uregs[2]
#define ARM_r1          uregs[1]
#define ARM_r0          uregs[0]
#define ARM_ORIG_r0     uregs[17]

#define HELPSTR "error usage: %s -p PID -l LIBNAME [-d (debug on)] [-z (zygote)] [-m (no mprotect)] [-s (appname)] [-Z (trace count)] [-D (debug level)]\n"

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	struct pt_regs2 regs;
	unsigned long dlopenaddr, mprotectaddr, codeaddr, libaddr;
	unsigned long *p;
	int fd = 0;
	int n = 0;
	char buf[32];
	char *arg;
	int opt;
	char *appname = 0;
 	//正常使用为./hijack -d -p PID -l /data/local/tmp/libexample.so,使用了-p -d -l选项
 	while ((opt = getopt(argc, argv, "p:l:dzms:Z:D:")) != -1) {
		switch (opt) {
			case 'p':
				pid = strtol(optarg, NULL, 0);
				break;
			case 'Z':
				zygote = strtol(optarg, NULL, 0);
			break;
			case 'D':
				debug = strtol(optarg, NULL, 0);
			break;
			case 'l':
				n = strlen(optarg)+1;
				n = n/4 + (n%4 ? 1 : 0);
				arg = malloc(n*sizeof(unsigned long));
				memcpy(arg, optarg, n*4);
				break;
			case 'm':
				nomprotect = 1;
				break;
			case 'd':
				debug = 1;
				break;
			case 'z':
				zygote = 1;
				break;
			case 's':
				zygote = 1;
				appname = strdup(optarg);
				break;
			default:
				fprintf(stderr, HELPSTR, argv[0]);

				exit(0);
				break;
		}
	}

	if (pid == 0 || n == 0) {
		fprintf(stderr, HELPSTR, argv[0]);
		exit(0);
	}

	if (!nomprotect) {
		if (0 > find_name(pid, "mprotect", &mprotectaddr)) {
			printf("can't find address of mprotect(), error!\n");
			exit(1);
		}
		if (debug)
			printf("mprotect: 0x%x\n", mprotectaddr);
	}

	void *ldl = dlopen("libdl.so", RTLD_LAZY);
	if (ldl) {
		dlopenaddr = (unsigned long)dlsym(ldl, "dlopen");
		dlclose(ldl);
	}
	unsigned long int lkaddr;
	unsigned long int lkaddr2;
	find_linker(getpid(), &lkaddr);
	//printf("own linker: 0x%x\n", lkaddr);
	//printf("offset %x\n", dlopenaddr - lkaddr);
	find_linker(pid, &lkaddr2);
	//printf("tgt linker: %x\n", lkaddr2);
	//printf("tgt dlopen : %x\n", lkaddr2 + (dlopenaddr - lkaddr));
	dlopenaddr = lkaddr2 + (dlopenaddr - lkaddr);
	/*
	以上代码首先获取自身进程中dlopen函数相对于linker在内存中的偏移地址，
	再获取目标进程中linker在内存中的地址，最后计算出目标进程中dlopen函数的地址
	*/
	if (debug)
		printf("dlopen: 0x%x\n", dlopenaddr);

	// Attach 
	if (0 > ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		printf("cannot attach to %d, error!\n", pid);
		exit(1);
	}
	waitpid(pid, NULL, 0);
	
	if (appname) {	
                //PTRACE_OTRACEFORK表示被跟踪的进程下次调用fork时停止，并自动跟踪新产生的进程
		if (ptrace(PTRACE_SETOPTIONS, pid, (void*)1, (void*)(PTRACE_O_TRACEFORK))) {
			printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)");
			return -1;
		}
		ptrace(PTRACE_CONT, pid, (void*)1, 0);//PTRACE_CONT表示子进程继续执行

		int t;
		int stat;
		int child_pid = 0;
		for (;;) {
			t = waitpid(-1, &stat, __WALL|WUNTRACED);

			if (t != 0 && t == child_pid) {
				if (debug > 1)
					printf(".");
				char fname[256];
				sprintf(fname, "/proc/%d/cmdline", child_pid);// #/proc/pid/cmdline文件中保存的是启动进程时使用的命令
				int fp = open(fname, O_RDONLY);
				if (fp < 0) {
					//PTRACE_SYSCALL和PTRACE_CONT等价，但是会在下一个系统调用或者进程退出时暂停
					ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
					continue;
				}
				read(fp, fname, sizeof(fname));
				close(fp);

				if (strcmp(fname, appname) == 0) {
					//appname是使用-s选项指定的
					if (debug)
						printf("zygote -> %s\n", fname);

					// detach from zygote
					ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT);

					// now perform on new process
					pid = child_pid;
					break;
				}
				else {
					ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
					continue;
				}
			}

			if (WIFSTOPPED(stat) && (WSTOPSIG(stat) == SIGTRAP)) {
				if ((stat >> 16) & PTRACE_EVENT_FORK) {
					if (debug > 1)
						printf("fork\n");
					int b = t; // save parent pid
					ptrace(PTRACE_GETEVENTMSG, t, 0, &child_pid);
					if (debug)
						printf("PID=%d  child=%d\n", t, child_pid);
					t = child_pid;
					
					if (debug > 1)
						printf("continue parent (zygote) PID=%d\n", b);
					ptrace(PTRACE_CONT, b, (void*)1, 0);

					ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
				}
			}
		}
	}

	if (zygote) {
		int i = 0;
		for (i = 0; i < zygote; i++) {
			// -- zygote fix ---
			// we have to wait until the syscall is completed, IMPORTANT!
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			if (debug > 1)
				printf("/");
			waitpid(pid, NULL, 0);

			ptrace(PTRACE_GETREGS, pid, 0, &regs);	
			if (regs.ARM_ip != 0) {
				if (debug > 1)
					printf("not a syscall entry, wait for entry\n");
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
				waitpid(pid, NULL, 0);
			}

			//if (debug)
			//	printf("process mode: currently waiting in SYSCALL\n");
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			if (debug > 1)
				printf("\\");
			waitpid(pid, NULL, 0);
			//if (debug)
			//	printf("process mode: SYSCALL completed now inject\n");
			// ---- need to work with zygote --- end ---
		}
	}
	if (debug > 1)
		printf("\n");

	sprintf(buf, "/proc/%d/mem", pid);
	fd = open(buf, O_WRONLY);
	if (0 > fd) {
		printf("cannot open %s, error!\n", buf);
		exit(1);
	}
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	//PTRACE_GETREGS用来读取所用17个寄存器的值存放在regs中

	// setup variables of the loading and fixup code	
	/*
	sc[9] = regs.ARM_r0;
	sc[10] = regs.ARM_r1;
	sc[11] = regs.ARM_lr;
	sc[12] = regs.ARM_pc;
	sc[13] = regs.ARM_sp;
	sc[15] = dlopenaddr;
	*/
	
	sc[11] = regs.ARM_r0;
	sc[12] = regs.ARM_r1;
	sc[13] = regs.ARM_r2;
	sc[14] = regs.ARM_r3;
	sc[15] = regs.ARM_lr;
	sc[16] = regs.ARM_pc;
	sc[17] = regs.ARM_sp;
	sc[19] = dlopenaddr;
		
	if (debug) {
		printf("pc=%x lr=%x sp=%x fp=%x\n", regs.ARM_pc, regs.ARM_lr, regs.ARM_sp, regs.ARM_fp);
		printf("r0=%x r1=%x\n", regs.ARM_r0, regs.ARM_r1);
		printf("r2=%x r3=%x\n", regs.ARM_r2, regs.ARM_r3);
	}

	// push library name to stack
	libaddr = regs.ARM_sp - n*4 - sizeof(sc);
	//这里堆栈指针向下移动n*4(so名称长度),sizeof(sc)(sc数组长度),计算想目标进程堆栈中写数据的地址
	sc[18] = libaddr;	
	//sc[14] = libaddr;
	//printf("libaddr: %x\n", libaddr);

	/*
	stack_start应该已经通过load_memmap获取了，这里如果没有获取到的话才会走下面的分支
	*/
	if (stack_start == 0) {
		stack_start = (unsigned long int) strtol(argv[3], NULL, 16);
		stack_start = stack_start << 12;
		stack_end = stack_start + strtol(argv[4], NULL, 0);
	}
	if (debug)
		printf("stack: 0x%x-0x%x leng = %d\n", stack_start, stack_end, stack_end-stack_start);
	
	// write library name to stack
	if (0 > write_mem(pid, (unsigned long*)arg, n, libaddr)) {
		//arg是so名称写到目标进程的堆栈中
		printf("cannot write library name (%s) to stack, error!\n", arg);
		exit(1);
	}
	
	// write code to stack
	codeaddr = regs.ARM_sp - sizeof(sc);
	if (0 > write_mem(pid, (unsigned long*)&sc, sizeof(sc)/sizeof(long), codeaddr)) {
		//sc是我们自己构造的机器码数组，写到目标进程的堆栈中
		printf("cannot write code, error!\n");
		exit(1);
	}
	
	if (debug)
		printf("executing injection code at 0x%x\n", codeaddr);

	// calc stack pointer
	//上面向目标进程写了n*4+sizeof(sc)字节的内容，对目标进程的堆栈指针进行扩充，一般堆栈是向低地址扩展的，所以用减法
	regs.ARM_sp = regs.ARM_sp - n*4 - sizeof(sc);

/*
下面的代码是调用mprotect修改整个堆栈段权限，
首先是第一个参数stack_start,起始地址
第二个参数长度
第三个参数PROT_READ|PROT_WRITE|PROT_EXEC  可读可写可执行
最后把之前获取到的mprotectaddr的地址赋值给pc寄存器，进行函数调用
在调用之前还把codeaddr的地址赋值给lr寄存器，当mprotect函数执行完毕之后就会返回到codeaddr处
codeaddr = regs.ARM_sp - sizeof(sc)
也就是说mprotect执行完之后会去执行我们在sc中构造的语句
*/
	// call mprotect() to make stack executable
	regs.ARM_r0 = stack_start; // want to make stack executable
	//printf("r0 %x\n", regs.ARM_r0);
	regs.ARM_r1 = stack_end - stack_start; // stack size
	//printf("mprotect(%x, %d, ALL)\n", regs.ARM_r0, regs.ARM_r1);
	regs.ARM_r2 = PROT_READ|PROT_WRITE|PROT_EXEC; // protections

	// normal mode, first call mprotect
	if (nomprotect == 0) {
		if (debug)
			printf("calling mprotect\n");
		regs.ARM_lr = codeaddr; // points to loading and fixing code
		regs.ARM_pc = mprotectaddr; // execute mprotect()
	}
	// no need to execute mprotect on old Android versions
	else {
		regs.ARM_pc = codeaddr; // just execute the 'shellcode'
	}
	
	// detach and continue
	ptrace(PTRACE_SETREGS, pid, 0, &regs);//为指定进程设置寄存器
	ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT);//结束跟踪

	if (debug)
		printf("library injection completed!\n");
	
	return 0;
}
