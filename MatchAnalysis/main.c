//
//  main.c
//  MatchAnalysis
//
//  Created by 黄文海 on 2018/1/23.
//  Copyright © 2018年 huang. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "Util.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<stdlib.h>

int fd;
char buffer[bufferSize];
struct symtab_command symtabCommand;
long readIndex = 0;


long readFile()
{
    long size = 0;
    size = read(fd, buffer, bufferSize);
    if (size == -1)
    {
        perror("read error");
        exit(0);
    }
    return size;
}

int readData(char* paddBuffer,int byteCount,int isAddOffset)
{
    if (paddBuffer == NULL || byteCount <= 0)
    {
        return -1;
    }
    
    int readCount = 0;
    int offset = byteCount;
    
    while (byteCount--)
    {
        if (readIndex >= 1024)
        {
            long size = readFile();
            if (size == 0) {
                return readCount;
            }
            readIndex = 0;
        }
        
        *(paddBuffer++) = buffer[readIndex++];
        readCount++;
    }
    
    if (isAddOffset == 0)
    {
        readIndex -= offset;
    }
    
    return readCount;
}

void analysisHeader(struct mach_header_64 header)
{
    printf("---------------------分析文件头部---------------------\n");
    if (header.magic == 0xfeedfacf)
    {
        printf("魔数 =  MH_MAGIC_64\n");
    }
    else
    {
        printf("魔数 = MH_CIGAM_64\n");
    }
    printf("cpu 类型 = CPU_TYPE_X86_64\n");
    printf("对应的具体类型 = %#x\n",header.cpusubtype);
    printf("文件类型 = %#x\n",header.filetype);
    printf("加载命令的数量 = %u\n",header.ncmds);
    printf("所有的加载命令大小 = %u\n",header.sizeofcmds);
    printf("标志位(标示文件的一些属性，如是需要重定位) = %#x\n",header.flags);
    
}

void parseSection()
{
    struct section_64 section;
    readData((char*)(&section), sizeof(struct section_64), 1);
    printf("section---------------------分析%s---------------------\n",section.sectname);
    printf("sectionName = %s\n",section.sectname);
    printf("segmentName = %s\n",section.segname);
    printf("section的开始的虚拟地址 = %#llx\n",section.addr);
    printf("section的大小 = %lld\n",section.size);
    printf("section加载内容在文件的偏移位置(不包括文件头和 load command部分) = %u\n",section.offset);
    printf("section的内存对齐 = %u(其虚拟地址必须是2^%u的整数倍，不够填0)\n",section.align,section.align);
    printf("section的重定位符号表的位置 = %u\n",section.reloff);
    printf("section的重定位符号表项的数量 = %u\n",section.nreloc);
    printf("section的类型和属性 = %#x(最低位的字节代表类型，每个section 只有一个类型，其余字节代表属性\n)",section.flags);
    printf("section中的符号在间接符号表中的下标，只有在是符号类型和 stub 类型的时候有意义 = %u\n",section.reserved1);
    printf("section类型为 Stubs的大小 = %u(只有section 类型为 stub 才有意义)\n",section.reserved2);
    printf("\n");
    
}

void parseSegment()
{
    struct segment_command_64 segment;
    readData((char*)(&segment), sizeof(struct segment_command_64), 1);
    printf("segment---------------------分析%s---------------------\n",segment.segname);
    printf("segment的大小 = %u\n",segment.cmdsize);
    printf("segment的名字 = %s\n",segment.segname);
    printf("segment的开始虚拟地址 = %#llx\n",segment.vmaddr);
    printf("segment的虚拟地址大小 = %llu\n",segment.vmsize);
    printf("segment在文件内的偏移 = %llu(这个文件偏移不包括可执行文件的头部，和加载命令部分)\n",segment.fileoff);
    printf("segment的大小 = %llu\n",segment.filesize);
    printf("segment的所有可用的保护属性(可读、可写、可执行) = %#x\n",segment.maxprot);
    printf("segment的只是要拥有的保护属性 = %#x\n",segment.initprot);
    printf("segment的子段的数量(操作系统把访问属性相近的 section 合并成 segment 减少页内碎片) = %u\n",segment.nsects);
    printf("segment的属性标识(段的内存分配特性等，一般为空) = %u\n",segment.flags);
    
    printf("==================下面分析 section=================\n");
    
    for (int i = 0; i < segment.nsects; i++)
    {
        parseSection();
    }
    
}

void parseDYLDINFO()
{
    struct dyld_info_command dyld;
    readData((char*)(&dyld), sizeof(struct dyld_info_command), 1);
    printf("------------------------LC_DYLD_INFO_ONLY------------------------\n");
    printf("装载时重定位信息的偏移地址 = %u\n",dyld.rebase_off);
    printf("装载时重定位信息的大小 = %u\n",dyld.rebase_size);
    printf("装载时链接信息的偏移地址 = %u\n",dyld.bind_off);
    printf("装载时链接信息的大小 = %u\n",dyld.bind_size);
    printf("弱链接信息的偏移地址 = %u\n",dyld.weak_bind_off);
    printf("若链接信息的大小 = %u\n",dyld.weak_bind_size);
    printf("延迟加载符号信息偏移地址 = %u\n",dyld.lazy_bind_off);
    printf("延迟加载符号信息大小 = %u\n",dyld.lazy_bind_size);
    printf("导出符号信息偏移 = %u\n",dyld.export_off);
    printf("导出符号信息大小 = %u\n\n",dyld.export_size);
    
    
}

void parseLCSYMTAB()
{
    readData((char*)(&symtabCommand), sizeof(struct symtab_command), 1);
    printf("------------------------LC_SYMTAB------------------------\n");
    printf("符号表在文件内偏移 = %u\n",symtabCommand.symoff);
    printf("符号表的项数 = %u\n",symtabCommand.nsyms);
    printf("字符串表在文件内的偏移 = %u\n",symtabCommand.stroff);
    printf("字符串表的大小 = %u\n\n",symtabCommand.strsize);
}

void parseLCDYSYMTAB()
{
    struct dysymtab_command dysymtab;
    readData((char*)(&dysymtab), sizeof(struct dysymtab_command), 1);
    printf("------------------------LC_DYSYMTAB------------------------\n");
    printf("局部符号在符号表里的开始下标 = %u\n",dysymtab.ilocalsym);
    printf("局部符号的数量 = %u\n",dysymtab.nlocalsym);
    printf("对外暴露的符号的在符号表里开始的下标 = %u\n",dysymtab.iextdefsym);
    printf("对外暴露的符号数量 = %u\n",dysymtab.nextdefsym);
    printf("未定义符号在符号表里开始的下标 = %u\n",dysymtab.iundefsym);
    printf("未定义符号在符号表里的数量 = %u\n",dysymtab.nundefsym);
    printf("内容表的偏移地址 = %#x\n",dysymtab.tocoff);
    printf("内容表有几项 = %u\n",dysymtab.ntoc);
    printf("模块表的偏移地址 = %#x\n",dysymtab.modtaboff);
    printf("模块表的项数 = %u\n",dysymtab.nmodtab);
    printf("引用符号表偏移 = %#x\n",dysymtab.extrefsymoff);
    printf("引用符号表的项数 = %u\n",dysymtab.nextrefsyms);
    printf("间接符号表偏移 = %#x\n",dysymtab.indirectsymoff);
    printf("间接符号表项的数量 = %u\n",dysymtab.nindirectsyms);
    printf("本地符号重定位表偏移 = %#x\n",dysymtab.locreloff);
    printf("本地符号重定位表的数量 = %u\n",dysymtab.nlocrel);
    printf("外部重定位符号表偏移 = %#x\n",dysymtab.extreloff);
    printf("外部重定位符表项数量 = %u\n\n",dysymtab.nextrel);
}

void parseLCLOADDYLINKER()
{
    struct dylinker_command linker;
    readData((char*)(&linker), sizeof(struct dylinker_command), 1);
    printf("------------------------LC_LOAD_DYLINKER------------------------\n");
    char name[linker.cmdsize - linker.name.offset];
    readData(name, (int)sizeof(name), 1);
    printf("链接器加载路径 = %s\n",name);
    printf("\n");
}

void parseLCUUID()
{
    struct uuid_command uuid;
    readData((char*)(&uuid), sizeof(struct uuid_command), 1);
    printf("-----------------------LC_UUID----------------------------------\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%x",uuid.uuid[i]);
    }
    printf("\n");
    
}

void parseLCVERSION()
{
    struct version_min_command versionMin;
    readData((char*)(&versionMin), sizeof(struct version_min_command), 1);
    printf("-----------------------platform version----------------------------------\n");
    printf("版本号 = %d.%d.%d\n",versionMin.version>>16,(versionMin.version&0x0000ff00)>>8,versionMin.version&0x000000ff);
    printf("SDK = %d.%d.%d\n",versionMin.sdk>>16,(versionMin.sdk&0x0000ff00)>>8,versionMin.sdk&0x000000ff);
    printf("\n");

}

void parseLCSOURCEVERSION()
{
    struct source_version_command source;
    readData((char*)(&source), sizeof(struct source_version_command), 1);
    printf("-----------------------Source version----------------------------------\n");
    uint64_t version = source.version;
    int e = version & 0x3ff;
    version>>=10;
    int d = version & 0x3ff;
    version>>=10;
    int c = version & 0x3ff;
    version>>=10;
    int b = version & 0x3ff;
    version>>=10;
    int a = (int)version;

    printf("资源版本号 = %d.%d.%d.%d.%d\n",a,b,c,d,e);
    printf("\n");

}

void parseLCMAIN()
{
    struct entry_point_command entry;
    readData((char*)(&entry), sizeof(struct entry_point_command), 1);
    printf("-----------------------LC_MAIN----------------------------------\n");
    printf("程序的入口地址偏移 = %#llx\n",entry.entryoff);
    printf("主线程需要的栈大小 = %llu\n\n",entry.stacksize);
}

void parseLinkeditData()
{
    struct linkedit_data_command linkedit;
    readData((char*)(&linkedit), sizeof(struct linkedit_data_command), 1);
    printf("----------------------LinkeditData------------------------------\n");
    printf("__LINKEDIT segment数据偏移 = %#x\n",linkedit.dataoff);
    printf("__LINKEDIT segment数据大小 = %u\n\n",linkedit.datasize);
    
}

void parseLCLOADDYLIB()
{
    struct dylib_command dylibComand;
    readData((char*)(&dylibComand), sizeof(struct dylib_command), 1);
    printf("----------------------LC_LOAD_DYLIB------------------------------\n");
    char name[dylibComand.cmdsize - dylibComand.dylib.name.offset];
    readData(name, (int)sizeof(name), 1);
    printf("动态库的加载路径 = %s\n",name);
    printf("动态库被创建时间 = %u\n",dylibComand.dylib.timestamp);
    printf("版本号 = %d.%d.%d\n",dylibComand.dylib.current_version>>16,(dylibComand.dylib.current_version&0x0000ff00)>>8,dylibComand.dylib.current_version&0x000000ff);
    
    printf("兼容版本号 = %d.%d.%d\n\n",dylibComand.dylib.compatibility_version>>16,(dylibComand.dylib.compatibility_version&0x0000ff00)>>8,dylibComand.dylib.compatibility_version&0x000000ff);

}

void analysisLoadCommands(int ncmds)
{
    struct load_command command;
    for (int i = 0; i < ncmds; i++)
    {
        
        readData((char*)(&command), sizeof(struct load_command), 0);
        switch (command.cmd) {
            case 0x19:
                printf("加载LC_SEGMENT_64\n");
                parseSegment();
                break;
            
            case (0x80000000 | 0x22):
                printf("加载LC_DYLD_INFO_ONLY\n");
                parseDYLDINFO();
                break;
            
            case 0x2:
                printf("加载LC_SYMTAB\n");
                parseLCSYMTAB();
                break;
                
            case 0xb:
                printf("加载LC_DYSYMTAB\n");
                parseLCDYSYMTAB();
                break;
            
            case 0xe:
                printf("加载动态链接器LC_LOAD_DYLINKER\n");
                parseLCLOADDYLINKER();
                break;
                
            case 0x1b:
                printf("LC_UUID\n");
                parseLCUUID();
                break;
                
            case 0x24:
                printf("LC_VERSION_MIN_MACOSX\n");
                parseLCVERSION();
                break;
                
            case 0x25:
                printf("LC_VERSION_MIN_IPHONEOS\n");
                parseLCVERSION();
                break;
                
            case 0x30:
                printf("LC_VERSION_MIN_WATCHOS\n");
                parseLCVERSION();
                break;
                
            case 0x2F:
                printf("LC_VERSION_MIN_TVOS\n");
                parseLCVERSION();
                break;
                
            case 0x2A:
                printf("LC_SOURCE_VERSION\n");
                parseLCSOURCEVERSION();
                break;
                
            case 0x28|0x80000000:
                printf("LC_MAIN\n");
                parseLCMAIN();
                break;
            
            case 0x26:
                printf("LC_FUNCTION_STARTS\n");
                parseLinkeditData();
                break;
            
            case 0x1d:
                printf("LC_CODE_SIGNATURE\n");
                parseLinkeditData();
                break;
                
            case 0x1e:
                printf("LC_SEGMENT_SPLIT_INFO\n");
                parseLinkeditData();
                break;
                
            case 0x29:
                printf("LC_DATA_IN_CODE\n");
                parseLinkeditData();
                break;
            
            case 0x2B:
                printf("LC_DYLIB_CODE_SIGN_DRS\n");
                parseLinkeditData();
                break;
                
            case 0x2E:
                printf("LC_LINKER_OPTIMIZATION_HINT\n");
                parseLinkeditData();
                break;
                
            case 0xc:
                printf("LC_LOAD_DYLIB\n");
                parseLCLOADDYLIB();
                break;
                
            case 0x18 | 0x80000000:
                printf("LC_LOAD_WEAK_DYLIB\n");
                parseLCLOADDYLIB();
                break;
                
            case 0x1f | 0x80000000:
                printf("LC_REEXPORT_DYLIB\n");
                parseLCLOADDYLIB();
                break;
            default:
                printf("not found type = %d %d %u\n",command.cmdsize,i,command.cmd);
                exit(0);
                break;
        }
    }

}

int cmp1(struct nlist_64 * a,struct nlist_64 * b)
{
    return (int)(a->n_un.n_strx - b->n_un.n_strx);//a>b 返回正值
}

void analysisSymbolTable()
{
    lseek(fd, symtabCommand.symoff, SEEK_SET);
    readIndex = 0;
    memset(buffer, 0, sizeof(buffer));
    readFile();
    struct nlist_64 list[symtabCommand.nsyms];
    
    for (int i = 0; i < symtabCommand.nsyms; i++)
    {
        struct nlist_64 *temp = list + i;
        readData((char*)(temp), sizeof(struct nlist_64), 1);
    }
    
    qsort(list, symtabCommand.nsyms, sizeof(struct nlist_64), cmp1);
    lseek(fd, symtabCommand.stroff, SEEK_SET);
    readIndex = 0;
    memset(buffer, 0, sizeof(buffer));
    char stringTable[symtabCommand.strsize];
    readFile();
    readData(stringTable, symtabCommand.strsize, 1);
    for (int i = 0; i < symtabCommand.nsyms; i++)
    {
        printf("symbol name = ");
        int number;
        if (i != symtabCommand.nsyms - 1) {
            number = list[i + 1].n_un.n_strx - list[i].n_un.n_strx;
        }
        else {
            number = symtabCommand.strsize - list[i].n_un.n_strx;
        }
        
        int start = list[i].n_un.n_strx - 1;
        for (int j = 0; j < number; j++)
        {
            printf("%c",stringTable[j + start]);
        }
        printf("\n");
        printf("type = %#x\n",list[i].n_type);
        printf("section index(type 为N_SECT有效) = %u\n",list[i].n_sect);
        printf("description = %u\n",list[i].n_desc);
        printf("转载地址 = %llu\n\n",list[i].n_value);
    }
    printf("\n");
}

void startAnalysis()
{
    memset(buffer, 0, sizeof(buffer));
    readFile();
    struct mach_header_64 header;
    readData((char*)(&header), sizeof(header), 1);
    analysisHeader(header);
    analysisLoadCommands(header.ncmds);
    analysisSymbolTable();
}


int main(int argc, const char * argv[]) {
    
    if (argc == 2)
    {
        fd = open(argv[1], O_RDONLY);
    }
    else if (argc == 1)
    {
        fd = open("your mach-o path", O_RDONLY);
    }
    
    if (fd == -1)
    {
        perror("open fail error");
        return 0;
    }
    startAnalysis();

    close(fd);


    return 0;
}
