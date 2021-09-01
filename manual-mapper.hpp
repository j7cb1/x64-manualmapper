#ifndef MANUALMAPPER_HPP
#define MANUALMAPPER_HPP

#include <TlHelp32.h>
#include <Windows.h>
#include <cstdio>
#include <fstream>

namespace injector
{
    __int32 GetProcessId(const char* processname)
    {
        PROCESSENTRY32 Entry;
        Entry.dwSize = sizeof PROCESSENTRY32;

        HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (!Process32First(Snapshot, &Entry)) {
            return 0;
        }

        while (Process32Next(Snapshot, &Entry)) {

            if (strcmp(Entry.szExeFile, processname) == 0) {
                return (int)Entry.th32ProcessID;
            }
        }

        return 0;
    }

    __int8* ImagePathToBuffer(const char* path)
    {
        __int8* ReturnBuffer = nullptr;

        std::ifstream FileStream(path, std::ifstream::binary);
        if (FileStream) {

            FileStream.seekg(0, FileStream.end);
            __int64 SizeOfImage = FileStream.tellg();
            FileStream.seekg(0, FileStream.beg);

            ReturnBuffer = new __int8[SizeOfImage];
            if (!ReturnBuffer) {
                return nullptr;
            }
          
            FileStream.read(ReturnBuffer, SizeOfImage);
        }
       
        return ReturnBuffer;
    }

	class ManualMap
	{
	public:
        ManualMap(const char* path, const char* processname)
        {
            __int8* ImageBuffer = injector::ImagePathToBuffer(path);
            ManualMap(ImageBuffer, processname);
        }

        ManualMap(__int8* imagebuffer, const char* processname)
        {
            __int32 ProcessId = injector::GetProcessId(processname);
            if (!ProcessId) {
                printf("> invalid pid\n");
                return;
            } printf("> located pid %x : %s\n", ProcessId, processname);

            HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
            if (ProcessHandle == INVALID_HANDLE_VALUE) {
                printf("> invalid hanlde value\n");
                return;
            } printf("> opened handle to target process %p\n", ProcessHandle);

            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
            if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                printf("> invalid image dos signature\n");
                return;
            }

            PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(imagebuffer + DosHeader->e_lfanew);
            __int64 SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;

            void* Allocbase = VirtualAlloc(nullptr, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!Allocbase) {
                printf("> failed to allocate buffer to store new mapped image\n");
                return;
            }  
            memcpy(Allocbase, imagebuffer, NtHeaders->OptionalHeader.SizeOfHeaders);

            PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
            for (__int32 Idx = 0; Idx < NtHeaders->FileHeader.NumberOfSections; Idx++, SectionHeader++) {             
                void* SectionBase = (void*)((__int64)Allocbase + SectionHeader->VirtualAddress);
                void* Source = (void*)(imagebuffer + SectionHeader->PointerToRawData);
                memcpy(SectionBase, Source, SectionHeader->SizeOfRawData);
            } printf("> copied sections\n");

            PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((__int64)Allocbase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            if (!ImportDescriptor) {
                printf("> import descriptor is null\n");
                return;
            }

            while (ImportDescriptor->Name) {

                const char* ModuleName = (const char*)((__int64)Allocbase + ImportDescriptor->Name);
                HMODULE ModuleBaseAddress = LoadLibraryA(ModuleName);
                if (!ModuleBaseAddress) {
                    return;
                }

                PIMAGE_THUNK_DATA FirstThunkData = (PIMAGE_THUNK_DATA)((__int64)Allocbase + ImportDescriptor->FirstThunk);
                PIMAGE_THUNK_DATA OriginalFirstThunkData = (PIMAGE_THUNK_DATA)((__int64)Allocbase + ImportDescriptor->OriginalFirstThunk);

                if (!OriginalFirstThunkData && !FirstThunkData) {
                    return;
                }

                __int64 FunctionAddress = 0;
                while (OriginalFirstThunkData->u1.AddressOfData) {

                    const char* FunctionName = "";
                    if (IMAGE_SNAP_BY_ORDINAL(OriginalFirstThunkData->u1.Ordinal)) {
                        FunctionName = (const char*)(LOWORD(OriginalFirstThunkData->u1.Ordinal));
                        FunctionAddress = (__int64)(GetProcAddress(ModuleBaseAddress, FunctionName));
                    }

                    else {
                        PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((__int64)Allocbase + OriginalFirstThunkData->u1.AddressOfData);
                        FunctionName = ImportByName->Name;
                        FunctionAddress = (__int64)GetProcAddress(ModuleBaseAddress, ImportByName->Name);
                    }

                    if (FunctionAddress) {                  
                        FirstThunkData->u1.Function = FunctionAddress;
                    }

                    else {
                        printf("> failed to locate imported functions exported address\n");
                        return;
                    }

                    OriginalFirstThunkData++;
                    FirstThunkData++;
                }

                ImportDescriptor++;
            }  printf("> resolved imports\n");

            __int64 ImageBase = NtHeaders->OptionalHeader.ImageBase;
            void* RemoteAllocBase = VirtualAllocEx(ProcessHandle, (void*)imagebuffer, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!RemoteAllocBase) {

                RemoteAllocBase = VirtualAllocEx(ProcessHandle, nullptr, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (!RemoteAllocBase) {
                    printf("> failed to allocate memory in target process\n");
                    return;
                }

                PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)imagebuffer + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                if (BaseRelocation) {
                    return;
                }

                __int64 RelocationDelta = 0;
                if ((__int64)RemoteAllocBase < ImageBase) {
                    RelocationDelta = NtHeaders->OptionalHeader.ImageBase - (__int64)RemoteAllocBase;
                }

                else {
                    RelocationDelta = (__int64)RemoteAllocBase - NtHeaders->OptionalHeader.ImageBase;
                }

                while (BaseRelocation->VirtualAddress) {

                    __int32 RelocationEntryCount = BaseRelocation->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION) / sizeof(__int16);
                    __int16* Entry = (__int16*)(BaseRelocation + 1);

                    for (__int32 Idx = 0; Idx = RelocationEntryCount; Idx++) {

                        if (Entry[Idx] >> 0x0C == IMAGE_REL_BASED_DIR64) {
                            __int64 OffsetToRelocation = ((__int64)imagebuffer + BaseRelocation->VirtualAddress + (Entry[Idx] & 0xFFF));
                            *(__int64*)OffsetToRelocation += RelocationDelta;
                        }

                        Entry++;
                    }

                    BaseRelocation = (PIMAGE_BASE_RELOCATION)(BaseRelocation + BaseRelocation->SizeOfBlock);
                }

                printf("> resolved imports\n");
            }   

            else {
                printf("> relocations do not need relocating (skipping)\n");
            }

            SIZE_T BytesWritten = 0;
            if (!WriteProcessMemory(ProcessHandle, RemoteAllocBase, Allocbase, SizeOfImage, &BytesWritten)) {
                printf("> failed to write mapped image into target process\n");
                return;
            } printf("> written mapped image into target process\n");
  
         
            printf("> creating remote thread to call image entry\n");
            CreateRemoteThread(ProcessHandle, 0, 0, (LPTHREAD_START_ROUTINE)((__int64)RemoteAllocBase + NtHeaders->OptionalHeader.AddressOfEntryPoint), 0, 0, 0);
		}
	};
}

#endif 