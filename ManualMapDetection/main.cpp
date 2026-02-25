#include <Windows.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <cmath>
#include <string>

bool ManualMapDetection()
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (!hProcess)
        return false;

    auto NtQueryVirtualMemory = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory"));
    if (!NtQueryVirtualMemory)
    {
        CloseHandle(hProcess);
        return false;
    }

    std::vector<MEMORY_BASIC_INFORMATION> regions;
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T returned = 0;
    uintptr_t address = 0;

    while (NtQueryVirtualMemory(hProcess, reinterpret_cast<PVOID>(address), 0, &mbi, sizeof(mbi), &returned) == 0)
    {
        if (mbi.State == MEM_COMMIT)
            regions.push_back(mbi);

        address += mbi.RegionSize;
    }

    if (regions.empty())
    {
        CloseHandle(hProcess);
        return false;
    }

    auto IsExecutablePage = [](DWORD prot) -> bool 
    {
        return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
    };

    auto ProtectionToString = [](DWORD prot) -> std::string
    {
        if (prot == PAGE_EXECUTE_READWRITE) 
            return "RXW";
        if (prot == PAGE_EXECUTE_READ)
            return "RX";
        if (prot == PAGE_EXECUTE) 
            return "X";
        if (prot == PAGE_READWRITE) 
            return "RW";
        if (prot == PAGE_READONLY) 
            return "R";

        return "???";
    };

    constexpr double HIGH_ENTROPY_THRESHOLD = 7.75;
    constexpr SIZE_T ENTROPY_SAMPLE_SIZE = 4096;

    for (size_t i = 0; i < regions.size(); ++i)
    {
        const auto& region = regions[i];
        if (region.Type != MEM_PRIVATE)
            continue;

        bool is_exec = IsExecutablePage(region.Protect);
        if (is_exec)
        {
            if (region.RegionSize >= ENTROPY_SAMPLE_SIZE)
            {
                BYTE sample[ENTROPY_SAMPLE_SIZE]{};
                SIZE_T read = 0;
                if (ReadProcessMemory(hProcess, region.BaseAddress, sample, ENTROPY_SAMPLE_SIZE, &read) && read == ENTROPY_SAMPLE_SIZE)
                {
                    int hist[256] = { 0 };
                    for (SIZE_T j = 0; j < read; ++j) hist[sample[j]]++;

                    double ent = 0.0;
                    for (int k = 0; k < 256; ++k)
                    {
                        if (hist[k] == 0)
                            continue;

                        double p = static_cast<double>(hist[k]) / read;
                        ent -= p * std::log2(p);
                    }

                    if (ent >= HIGH_ENTROPY_THRESHOLD)
                    {
                        std::cout << "[manual_map] module detected in memory (high entropy)" << std::endl;
                    }
                }
            }

            size_t step = 1;
            while (i + step < regions.size())
            {
                const auto& nxt = regions[i + step];
                if (nxt.Type != MEM_PRIVATE) 
                    break;

                if (!IsExecutablePage(nxt.Protect) && nxt.Protect != PAGE_READWRITE && nxt.Protect != PAGE_READONLY)
                    break;

                step++;
            }

            std::cout << "[manual_map] module detected in memory (ErasePE)" << std::endl;
        }

        if (region.Protect == PAGE_READWRITE || region.Protect == PAGE_READONLY)
        {
            constexpr SIZE_T SCAN = 0x2000;
            BYTE buf[SCAN]{};
            SIZE_T rd = 0;
            if (ReadProcessMemory(hProcess, region.BaseAddress, buf, SCAN, &rd) && rd > 0x400)
            {
                for (SIZE_T off = 0; off <= 0x400 && off + 0x200 <= rd; off += 0x10)
                {
                    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf + off);
                    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                        continue;

                    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x800)
                        continue;

                    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buf + off + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.NumberOfSections > 0 && nt->FileHeader.NumberOfSections < 40)
                    {
                        std::cout << "[manual_map] module detected in memory (PE)";
                    }
                }
            }
        }
    }
}

int main()
{
    for (;;)
    {
        ManualMapDetection();

        Sleep(1);
    }
}