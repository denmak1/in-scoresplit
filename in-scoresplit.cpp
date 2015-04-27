#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <conio.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdint.h>
#include <TlHelp32.h>

#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <fstream>

// byte lengths for certain values
#define SCORE_LEN       4      // score is 4 bytes in memory
#define GRAZE_LEN       2      // graze is 2 bytes in memory
#define PIV_LEN         3      // piv is 3 bytes in memory
#define ITEM_LEN        2      // point items are 2 bytes in mem
#define TIME_LEN        2      // time counter is 2 bytes in mem
#define SCB_LEN         4      // spell card bonus is 4 bytes in mem
#define SC_MARK_LEN     3      // spell card marker is 2 bytes in mem
#define STAGE_NUM_LEN   1      // stage number

// static addresses
#define SCB_ADDR        0x004EA76C     // address for current SCB counter
#define SC_CAP_BON      0x004EA774     // SCB of the last spell capped
#define SCB_ACTIVE      0x004EA78C     // junk (?)
#define SC_MARKER       0x004EBC2D     // spell card trigger marker
                                       // 00 00 -> positive val at spell start
#define STAGE_NUM       0x004E4850     // 0 = stage 1, etc
#define STATIC_OFFSET   0x0120F510     // offset for static pointer to score

#define ITEMS_START     27689
#define PIV_START       3000000
#define POLL_RATE_MS    5

static const bool DEBUG = 0;
static const int buffer_size = 16;

std::ofstream logfile;
//std::ifstream infile;

// print address as hex string for debugging
std::string addrToHexStr(INT_PTR addr)
{    
    std::stringstream result;

    result << std::hex << std::uppercase << std::setfill('0');
    result << std::setw(sizeof(addr) * 2) << addr;

    return result.str();
}

// print memory buffer of bytes as hex string for debugging
std::string byteToHexStr(uint8_t* buffer, SIZE_T size)
{
    std::stringstream result;

    result << std::hex << std::uppercase << std::setfill('0');

    for(; size > 0; buffer++, size--) {
        result << std::setw(2) << (unsigned int) *buffer;
        if(size > 1) result << " ";
    }

    return result.str();
}

// use to convert a buffer of bytes of defined size into a long int
long bytesToInt(uint8_t* buffer, SIZE_T size)
{
    int old_size = size;
    unsigned long res_int;
    std::stringstream result;

    result << std::hex << std::uppercase << std::setfill('0');

    for(; size > 0; buffer++, size--)
        result << std::setw(2) << (unsigned int) *buffer;

    // std::cout << "resulting hex string = " << result.str() << std::endl;
    res_int = std::stoul(result.str(), nullptr, 16);
    
    // various return types follow:
    if(old_size == 1) return _byteswap_ulong(res_int) >> 32;    // lower 32
    if(old_size == 2) return _byteswap_ulong(res_int) >> 16;    // lower 16
    if(old_size == 3) return _byteswap_ulong(res_int) >> 8;     // lower 8
    else              return (long)_byteswap_ulong(res_int);    // full 64 bit
}

std::wstring GetAPIErrorMessage(DWORD error)
{
    LPWSTR errorText = NULL;

    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPWSTR)&errorText, 0, NULL);

    std::wstring result;
    if (NULL != errorText) {
        result = errorText;
        LocalFree(errorText);
    }

    return result;
}

bool printProcInfo(DWORD procID)
{
    TCHAR proc_name[MAX_PATH] = TEXT("[unknown pid]");

    HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               false, procID);

    MODULEINFO modinfo;
    LPVOID base_addr;

    if(hproc != NULL) {
        HMODULE hmod;
        DWORD cb;        

        if(EnumProcessModules(hproc, &hmod, sizeof(hmod), &cb)) {

            GetModuleBaseName(hproc, hmod, proc_name,
                              sizeof(proc_name) / sizeof(TCHAR));

            GetModuleInformation(hproc, hmod, &modinfo, cb);
            
            base_addr = modinfo.EntryPoint;
            // HMODULE temp = GetModuleHandle(proc_name);
            // addr = GetProcAddress(temp, "th08.exe");

        }
    }

    _tprintf(TEXT("%s  (PID: %u) entry addr: %x\n"), proc_name, procID,
             base_addr);

    // return true if this is the pid of th08.exe
    if(_tcscmp(proc_name, TEXT("th08.exe")) == 0)
        return true;
    else
        return false;
}

DWORD dwGetModuleBaseAddress(DWORD dwProcessIdentifier, TCHAR *lpszModuleName)
{
   HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                                               dwProcessIdentifier);
   DWORD dwModuleBaseAddress = 0;

   if(hSnapshot != INVALID_HANDLE_VALUE) {
      MODULEENTRY32 ModuleEntry32 = {0};
      ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

      if(Module32First(hSnapshot, &ModuleEntry32)) {
         do {
            if(_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0) {
               dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
               break;
            }
         }
         while(Module32Next(hSnapshot, &ModuleEntry32));
      }

      CloseHandle(hSnapshot);
   }

   return dwModuleBaseAddress;
}

int find2hu08()
{
    DWORD proc_ids[1024];
    DWORD cb;

    if(!EnumProcesses(proc_ids, sizeof(proc_ids), &cb))
        return false;

    DWORD proc_cnt = cb / sizeof(DWORD);

    for(int i = 0; i < proc_cnt; i++) {
        if(proc_ids[i] != 0) {
            if(printProcInfo(proc_ids[i]))
                return proc_ids[i];
        }
    }

    return 0;
}

void printErr()
{
    std::wcout << "mem read error: "
               << GetAPIErrorMessage(GetLastError())
               << std::endl;

    return;
}

int printAndUpdate(std::string str)
{
    logfile.open("my-best.txt", std::ios::app);
    logfile << str;
    logfile.close();

    return 0;    
}

int readFromFile(std::string cstr)
{
    // assign the numbers of current split into variables
    int c_line_num, c_score, c_graze, c_piv, c_items, c_time;
    std::stringstream c_ss(cstr);
    c_ss >> c_line_num >> c_score >> c_graze >> c_piv >> c_items >> c_time;

    std::string fstr;
    std::ifstream infile("my-best.txt");

    for(int i = 0; i < c_line_num; ++i)
        std::getline(infile, fstr);

    // assign numbers of matching split from file to variables
    int f_line_num, f_score, f_graze, f_piv, f_items, f_time;
    std::stringstream f_ss(fstr);
    f_ss >> f_line_num >> f_score >> f_graze >> f_piv >> f_items >> f_time;

    // display
    system("cls");
    printf(" %2d%8s | %10s\n", c_line_num, "curr", "best");
    printf("%10d0 |%10d0\n", c_score, f_score);
    printf("piv %7d | %10d\n", c_piv, f_piv);
    printf("graze %5d | %10d\n", c_graze, f_graze);
    printf("items  %4d | %10d\n", c_items, f_items);
    printf("time  %5d | %10d\n", c_time, f_time);

    printf("\n");

    infile.close();

    return 0;
}

int clearFile()
{
    logfile.open("my-best.txt", std::ofstream::out | std::ofstream::trunc);
    logfile.close();

    return 0;
}

int main(int argc, char* argv[])
{
    // find IN (th08.exe) address
    DWORD pid = find2hu08();
    printf("2hu pid found = %d\n", pid);

    // hooking process
    HANDLE proc_h = OpenProcess(PROCESS_VM_READ, false, pid);
    std::shared_ptr<void> managed_processHandle(proc_h, &CloseHandle);

    printf("2hu proc handle = 0x%x\n", proc_h);


    // buffers and stuff
    uint8_t buffer[buffer_size];
    SIZE_T bytes_read;

    // base address of the running program
    DWORD base_addr = dwGetModuleBaseAddress(pid, _T("th08.exe"));
    DWORD stat_offset = STATIC_OFFSET;

    // locate the dynamic high score memory address
    DWORD dynamic_addr_HSCR;
    ReadProcessMemory(proc_h, (LPCVOID)(base_addr+stat_offset),
                      &dynamic_addr_HSCR, sizeof(DWORD), &bytes_read);

    if(ReadProcessMemory(proc_h, (LPCVOID)dynamic_addr_HSCR, buffer,
                         buffer_size, &bytes_read)) {

        /* std::cout << "addr: " << addrToHexStr(dynamic_addr_HSCR)
                     << std::endl; */

        std::cout << "entry addr: " << byteToHexStr(buffer, 16)
                  << std::endl;
    }
    else printErr();
    

    // pointer to foreign address
    INT_PTR foreign_proc_addr = dynamic_addr_HSCR;

    // variables
    volatile int cur_sc_mark = 0, last_sc_mark = 0;          // spell card marker
    volatile int cur_sc_cap_bon = 0, last_sc_cap_bon = 0;    // last spell capped bonus
    volatile int cur_time = 0, last_time = 0;                // time
    volatile long cur_score = 0, last_score = 0;             // score (truncated 0)
    volatile int cur_stage = 0, last_stage = 0;              // stage number
    volatile int cur_graze = 0, cur_piv = 0, cur_items = 0;

    bool new_stage; // detect for new stage???
    bool restart;
    bool spell_split;
    int splitno = 1;

    std::stringstream to_file;

    while(1) {
        // set custom poll rate here
        Sleep(POLL_RATE_MS);

        // clear string stream for new line
        to_file.str("");
        foreign_proc_addr = dynamic_addr_HSCR;
        

        // clear buffer, read spell card marker
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)SC_MARKER, buffer,
                             buffer_size, &bytes_read))
            cur_sc_mark = bytesToInt(buffer, SC_MARK_LEN);
        else printErr();


        // clear buffer, read stage number
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)STAGE_NUM, buffer,
                             buffer_size, &bytes_read))
            cur_stage = bytesToInt(buffer, STAGE_NUM_LEN);
        else printErr();


        // clear buffer, read score
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)foreign_proc_addr, buffer,
                             buffer_size, &bytes_read))
            cur_score = bytesToInt(buffer, SCORE_LEN);
        else printErr();


        // add offset, clear buffer, read graze
        foreign_proc_addr += 0xC;
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)foreign_proc_addr, buffer,
                             buffer_size, &bytes_read))
            cur_graze = bytesToInt(buffer, GRAZE_LEN);
        else printErr();


        // add offset, clear buffer, read piv
        foreign_proc_addr += 0x18;
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)foreign_proc_addr, buffer,
                             buffer_size, &bytes_read))
            cur_piv = bytesToInt(buffer, PIV_LEN);
        else printErr();


        // add offset, clear buffer, read point items
        foreign_proc_addr += 0xC;
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)foreign_proc_addr, buffer,
                             buffer_size, &bytes_read))
            cur_items = bytesToInt(buffer, ITEM_LEN);
        else printErr();


        // add offset, clear buffer, read time
        foreign_proc_addr += 0xC;
        std::fill(buffer, buffer+buffer_size, 0);
        bytes_read = 0;

        if(ReadProcessMemory(proc_h, (LPCVOID)foreign_proc_addr, buffer,
                             buffer_size, &bytes_read))
            cur_time = bytesToInt(buffer, TIME_LEN);
        else printErr();


        // define conditions for printing splits here

        // new stage
        if(cur_stage - last_stage > 0 && cur_score != 0)
            new_stage = true;

        // esc r
        if(cur_score < last_score) {
            restart = true;
            splitno = 1;
        }

        // new spell start
        if(last_sc_mark - cur_sc_mark < 0 && cur_time != 0)
            spell_split = true;


        // print on conditions
        if(spell_split || new_stage || restart && cur_items != ITEMS_START) {
            to_file << splitno << " " << cur_score << " ";
            to_file << cur_graze << " ";
            to_file << cur_piv << " ";

            // printf("ITEMS: %d\n", bytesToInt(buffer, ITEM_LEN));
            to_file << cur_items << " ";

            // print time last
            // printf("TIME: %d\n\n", cur_time);
            to_file << cur_time << "\n";

            // update file if necessary
            //printAndUpdate(to_file.str());
            readFromFile(to_file.str());
            //printf("cur sc mark = %d\n", cur_sc_mark);
            // update counters after printing
            splitno++;
        }

        last_time = cur_time;
        last_score = cur_score;
        last_stage = cur_stage;
        last_sc_mark = cur_sc_mark;
        new_stage = false;
        restart = false;
        spell_split = false;
    }

    return 0;
}
