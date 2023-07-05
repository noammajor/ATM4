#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include "elf64.h"
#include <sys/reg.h>
//#include <elf.h>

#define    ET_NONE    0    //No file type
#define    ET_REL    1    //Relocatable file
#define    ET_EXEC    2    //Executable file
#define    ET_DYN    3    //Shared object file
#define    ET_CORE    4    //Core file


/* symbol_name        - The symbol (maybe function) we need to search for.
 * exe_file_name    - The file where we search the symbol in.
 * error_val        - If  1: A global symbol was found, and defined in the given executable.
 *             - If -1: Symbol not found.
 *            - If -2: Only a local symbol was found.
 *             - If -3: File is not an executable.
 *             - If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value        - The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

int compare(FILE* strtab_ptr, char* symbol_name) {
    char* symbol_name_temp = symbol_name;
    int ch = fgetc(strtab_ptr);
    while (*symbol_name_temp != '\0' || ch != 0) {
//        printf("%c", ch);
        if (ch != *symbol_name_temp) {
            return 0;
        }
        symbol_name_temp++;
        ch = fgetc(strtab_ptr);
    }
    if (*symbol_name_temp == '\0' && ch == 0)
        return 1;
//    printf("GOT OUT \n");
    return 0;
}

void start_BP_handler(pid_t child_pid, unsigned long addr, long data, int* wait_status, int* counter);
void end_BP_handler(pid_t child_pid,unsigned long long OG_rsp,unsigned long addr, int* wait_status, int* counter, unsigned long retAddress,
                    long retData){
    struct user_regs_struct regs;
    struct user_regs_struct regsTest;
    long data = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr, NULL); // updated address
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_CONT,child_pid,NULL,NULL);
    wait(wait_status);
    if(WIFEXITED(*wait_status)){
        return;
    }
    ptrace(PTRACE_GETREGS,child_pid,0,&regs);
    if(regs.rsp == OG_rsp){
        printf("PRF:: run #%d returned with %d\n",*counter, (int)regs.rax);
        regs.rip -=1;
        ptrace(PTRACE_SETREGS,child_pid,0,&regs);
        ptrace(PTRACE_POKETEXT,child_pid,(void*)retAddress,(void *)retData);//restoring the data in the end from the BP

        ptrace(PTRACE_POKETEXT,child_pid,(void*)addr,(void *)data_trap);// placing the break point in the beginning of the fun

        ptrace(PTRACE_CONT,child_pid,NULL,NULL);
        start_BP_handler(child_pid, addr, data, wait_status, counter);
    }
    else{
        regs.rip -=1;
        ptrace(PTRACE_SETREGS,child_pid,0,&regs);
        ptrace(PTRACE_POKETEXT,child_pid,(void*)retAddress,(void *)retData);
        ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
        wait(wait_status);
        long ret_data_trap = (retData & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT,child_pid,(void*)retAddress,(void *)ret_data_trap);// placing the break point at the end of the func
        end_BP_handler(child_pid, OG_rsp,addr,wait_status,counter,retAddress,retData);
    }

}

void start_BP_handler(pid_t child_pid, unsigned long addr, long data, int* wait_status, int* counter)
{   struct user_regs_struct regsTest;
    wait(wait_status);
    if(WIFEXITED(*wait_status))
        return;
    (*counter)++;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS,child_pid,0,&regs);
    ptrace(PTRACE_POKETEXT,child_pid,(void *)addr, (void*)data); // restoring the command
    regs.rip -=1;
    unsigned long long OG_rsp = regs.rsp + 8;
    int param1 = (int)regs.rdi;
    printf("PRF:: run #%d first parameter is %d\n",*counter,param1);
    unsigned long long rsp = regs.rsp;
    ptrace(PTRACE_SETREGS,child_pid,0,&regs);
    unsigned long retAddress = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)rsp, NULL);
    long retData = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)retAddress, NULL);
    long ret_data_trap = (retData & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT,child_pid,(void*)retAddress,(void *)ret_data_trap);// placing the break point at the end of the func
    end_BP_handler(child_pid,OG_rsp, addr, wait_status, counter, retAddress, retData);
}

unsigned long find_GOT_entry(char* symbol_name, char* exe_file_name, int* error_val){
    Elf64_Ehdr ELF_header;
    Elf64_Shdr sh_string_table_entry;
    Elf64_Off sh_string_table_entry_offset;
    Elf64_Off sh_string_table_offset;
    Elf64_Xword sh_string_table_size;
    Elf64_Shdr sh_entry;
    FILE * ELF_file = fopen(exe_file_name,"r");




    fread(&ELF_header,sizeof(Elf64_Ehdr),1,ELF_file);
    sh_string_table_entry_offset = ELF_header.e_shoff + ELF_header.e_shstrndx * sizeof(Elf64_Shdr);//the entry of shstrtab in the section header table
    fseek(ELF_file, sh_string_table_entry_offset,SEEK_SET);
    fread(&sh_string_table_entry,sizeof(Elf64_Shdr),1,ELF_file);
    sh_string_table_size = sh_string_table_entry.sh_size;
    sh_string_table_offset = sh_string_table_entry.sh_offset; // this is the offset of the shstrtab in the file

    fseek(ELF_file, ELF_header.e_shoff,SEEK_SET);
    // char* dynamic_symbol_table_string = ".dynsym";

    if(ELF_header.e_type != 2){
        *error_val = -3;
        return  0;
    }

    char BUFF[sh_string_table_size];

    int index_in_shstrtab;

    Elf64_Off offset_of_dynamic_symbol_table;
    Elf64_Off plt_offset;

    for(int i=0;i<ELF_header.e_shnum ; i++){
        fread(&sh_entry,sizeof(Elf64_Shdr),1,ELF_file);
        index_in_shstrtab = sh_entry.sh_name;
        Elf64_Off string_to_check_offset = sh_string_table_offset + index_in_shstrtab;
        fseek(ELF_file,string_to_check_offset,SEEK_SET);
        fgets(BUFF, sizeof(BUFF), ELF_file);
        if (strcmp(BUFF, ".dynsym") == 0){
            offset_of_dynamic_symbol_table =  sh_entry.sh_offset;
            break;
        }
        fseek(ELF_file,ELF_header.e_shoff+(i+1)*sizeof(Elf64_Shdr),SEEK_SET);
    }

    Elf64_Shdr dynamic_string_symbol_table;
    fseek(ELF_file, ELF_header.e_shoff+sh_entry.sh_link*sizeof(Elf64_Shdr),SEEK_SET);
    fread(&dynamic_string_symbol_table,sizeof(Elf64_Shdr),1,ELF_file);
    Elf64_Xword  size_of_dynmic_strtab= dynamic_string_symbol_table.sh_size;

    fseek(ELF_file, ELF_header.e_shoff,SEEK_SET);
    for(int i=0;i<ELF_header.e_shnum ; i++){
        fread(&sh_entry,sizeof(Elf64_Shdr),1,ELF_file);
        index_in_shstrtab = sh_entry.sh_name;
        Elf64_Off string_to_check_offset = sh_string_table_offset + index_in_shstrtab;
        fseek(ELF_file,string_to_check_offset,SEEK_SET);
        fgets(BUFF, sizeof(BUFF), ELF_file);
        if (strcmp(BUFF, ".rela.plt") == 0){
            plt_offset = sh_entry.sh_offset;
            break;
        }
        fseek(ELF_file,ELF_header.e_shoff+(i+1)*sizeof(Elf64_Shdr),SEEK_SET);
    }


    int size_of_plt = sh_entry.sh_size;
    int num_of_plt_entries = size_of_plt / sizeof(Elf64_Rela);


    /* plt */

    fseek(ELF_file,plt_offset,SEEK_SET);
    Elf64_Rela plt_entry;
    Elf64_Sym symbol_entry;
    int index_in_dysimytab;
    int index_in_dynamic_string_symbol_table;
    char BUFF2[size_of_dynmic_strtab];
    for(int i=0; i< num_of_plt_entries; i++){
        fread(&plt_entry,sizeof(Elf64_Rela),1,ELF_file);
        index_in_dysimytab = ELF64_R_SYM(plt_entry.r_info);
        fseek(ELF_file,offset_of_dynamic_symbol_table + index_in_dysimytab*(sizeof (Elf64_Sym)),SEEK_SET);
        fread(&symbol_entry,sizeof (Elf64_Sym),1,ELF_file);
        index_in_dynamic_string_symbol_table = symbol_entry.st_name;
        fseek(ELF_file,dynamic_string_symbol_table.sh_offset + index_in_dynamic_string_symbol_table,SEEK_SET);
        fgets(BUFF2, sizeof(BUFF2), ELF_file);
        //   printf("the string i scanned is %s\n", BUFF2);
        if (strcmp(BUFF2, symbol_name) == 0) {
            //    printf("i found %s in the rela.plt. \n",symbol_name);
            break;
        }
        fseek(ELF_file,plt_offset + (i + 1) * sizeof(Elf64_Rela)   ,SEEK_SET);
    }

    /** --------------------- now plt entry holds the right entry ------------------------*/
    //printf("i ended the for loop!! and ran for %d times\n", num_of_plt_entries);
    return plt_entry.r_offset;
}

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    int return_val = 0;
    FILE* header_ptr = fopen(exe_file_name, "rb");
    Elf64_Ehdr elf_header;
    fread(&elf_header, sizeof(elf_header), 1, header_ptr);
    if (elf_header.e_type != ET_EXEC) {
        *error_val = -3;
        fclose(header_ptr);
        return return_val;
    }

    FILE* section_ptr = fopen(exe_file_name, "rb");
    FILE* symbtab_ptr = fopen(exe_file_name, "rb");
    FILE* strtab_ptr = fopen(exe_file_name, "rb");

    Elf64_Shdr sh;
    fseek(section_ptr, elf_header.e_shoff, SEEK_SET);
    for (int i=0; i<elf_header.e_shnum; i++) {
        fread(&sh, sizeof(sh), 1, section_ptr);
        if (sh.sh_type == 0x2) {
            break;
        }
    }

    Elf64_Sym symtab_header;
    int symtab_local=0, is_symbol=0;
    fseek(symbtab_ptr, sh.sh_offset, SEEK_SET);
    for (int i=0; i<(sh.sh_size/sh.sh_entsize); i++) {
        fread(&symtab_header, sizeof(symtab_header), 1, symbtab_ptr);
        fseek(strtab_ptr, sh.sh_offset+sh.sh_size+symtab_header.st_name, SEEK_SET);
        if (compare(strtab_ptr, symbol_name)) {
            is_symbol = 1;
            if (ELF64_ST_BIND(symtab_header.st_info) == 1) {
                symtab_local = 0;
                break;
            }
            if (ELF64_ST_BIND(symtab_header.st_info) == 0) {
                symtab_local = 1;
            }
        }
    }
    if (symtab_local == 1) {
        *error_val = -2;
    }
    else if (!is_symbol) {
        *error_val = -1;
    }
    else if (symtab_header.st_shndx == SHN_UNDEF) {
        *error_val = -4;
    }
    else {
        *error_val = 1;
        return_val = symtab_header.st_value;
    }

    fclose(header_ptr);
    fclose(section_ptr);
    fclose(symbtab_ptr);
    fclose(strtab_ptr);
    return return_val;
}
pid_t run_target(char* const arg[]) {
    pid_t pid;
    pid = fork();
    if (pid > 0)
        return pid;
    else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execvp(arg[0], arg);
    } else {
        perror("fork");
        exit(1);
    }
}

void run_debugger(pid_t child_pid,long ad, bool isShared)
{
    int wait_status;
    struct user_regs_struct regs;
    int call_counter = 0;
    unsigned long addr = ad;
    unsigned long plt_address;
    long data;
    wait(&wait_status);
    if(WIFEXITED(wait_status))
        return;

    if(isShared==true){
        plt_address = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr, NULL);
        data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)plt_address, NULL);
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT,child_pid,(void*)plt_address,(void *)data_trap);
        ptrace(PTRACE_CONT,child_pid,NULL,NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status))
        {
            return;
        }
        ++call_counter;
        ptrace(PTRACE_POKETEXT,child_pid,(void*)plt_address, (void*)data);
        ptrace(PTRACE_GETREGS,child_pid,0,&regs);
        regs.rip -=1;
        unsigned long long original_rsp = regs.rsp + 8;
        unsigned long long rsp = regs.rsp;
        ptrace(PTRACE_SETREGS,child_pid,0,&regs);

        printf("PRF:: run #%d first parameter is %d\n",call_counter, (int)regs.rdi);
    } else{
        data = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr, NULL);
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT,child_pid,(void*)addr,(void *)data_trap);
        ptrace(PTRACE_CONT,child_pid,NULL,NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status))
        {
            return;
        }
        ++call_counter;
        ptrace(PTRACE_POKETEXT,child_pid,(void*)addr, (void*)data);
        ptrace(PTRACE_GETREGS,child_pid,0,&regs);
        regs.rip -=1;
        unsigned long long original_rsp = regs.rsp + 8;
        unsigned long long rsp = regs.rsp;
        ptrace(PTRACE_SETREGS,child_pid,0,&regs);

        printf("PRF:: run #%d first parameter is %d\n",call_counter, (int)regs.rdi);
    }

    unsigned long retAddress = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)rsp, NULL);
    long retData = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)retAddress, NULL);
    if(isShared == true){// dynamic case
        unsigned long newData;
        unsigned long plt_entry_data = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr, NULL);
        do{
            ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
            wait(&wait_status);
            newData = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr, NULL);
        } while (newData == plt_entry_data);
        addr = newData;
    }
    unsigned long ret_data_trap = (retData & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT,child_pid,(void*)retAddress,(void*)ret_data_trap);// placing the break point at the end of the func
    end_BP_handler(child_pid,original_rsp,addr,&wait_status,&call_counter, retAddress, retData);

}



int main(int argc, char *const argv[]) {
    int err = 0;
    bool Shared = false;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);
    if(err==-3)
    {
        printf("PRF:: %c not an executable!\n",*argv[1]);
        return 0;
    }
    if(err==-1)
    {
        printf("PRF:: %c not found! :(/n",*argv[0]);
        return 0;
    }
    if(err==-2)
    {
        printf("PRF:: %c is not a global symbol!\n",*argv[0]);
        return 0;
    }
    if (err==-4)
    {
        addr = find_GOT_entry(argv[1], argv[2], &err);
        Shared = true;
    }
    pid_t pid = run_target(argv + 2);
    run_debugger(pid,addr, Shared);
    return 0;
}
