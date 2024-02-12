// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <winhttp.h>
#include <fstream>
#include <string>
#include <direct.h>
#include <TlHelp32.h>
#include <vector>
#include <process.h>
#include <thread>
#include <bitset>
#include <mutex>
#include <array>
#include <dwmapi.h>
#include <atlstr.h>
#include <stdlib.h>
#include<string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <iostream>
#include "SignatureScanner.h"
DWORD GetDwordFromBytes(byte* B, bool LittleEndian)
{
	if (!LittleEndian) { return (B[3]) | (B[2] << 8) | (B[1] << 16) | (B[0] << 24); }
	else { return (B[0]) | (B[1] << 8) | (B[2] << 16) | (B[3] << 24); }
}

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_stricmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}
int main()
{
	uintptr_t vmbase, vmunbase, entitylist, heap, heapvar, getkeyadd, rip, silent, glow, fov, render_outline, skill_struct_check, fnskillstruct, camera_manager, sens_ptr, real_vis, real_outline, visfn, outfn, visread, outread;


	int Size_of_in = 8;//vm xor base
	std::vector<BYTE> Data;
	Data.resize(Size_of_in);
	std::vector<BYTE> VMKEY;
	VMKEY.resize(10);
	std::vector<BYTE> HEAPKEY;
	HEAPKEY.resize(10);

	DWORD dwPID;
	GetWindowThreadProcessId(FindWindowA("TankWindowClass", NULL), &dwPID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);
	uintptr_t moduleBase = GetModuleBaseAddress(dwPID, "Overwatch.exe");
	SignatureScanner scanner = SignatureScanner(/*process:*/hProcess, /*start address:*/moduleBase/*,end address: (optional)*/);
	uintptr_t result;
	sens_ptr = 0;



	uintptr_t initray = scanner.scanEx("48 89 5C 24 ? 57 48 83 EC ? 33 DB C7 41");
	printf("init_ray_cast_struct :0x%llX\n", initray - moduleBase);

	result = scanner.scanEx(/*byte pattern:*/"E8 ? ? ? ? EB ? 33 C0 8B C8 49 8B ? 83 E0 ? 48 89 8D ? ? ? ? 48 83 F8 ? 0F 87 ? ? ? ? 8B 84 ? ?");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nFN_Raycast Func is Called at: 0x%llX\n", result - moduleBase);
	Size_of_in = 5;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	uintptr_t fn_ray_cast = ((uintptr_t)GetDwordFromBytes(&Data[1], 1) + Size_of_in + result - moduleBase) & 0xFFFFFFF;
	printf("FN_ray_cast Func: 0x%llX\n", fn_ray_cast);

	result = scanner.scanEx(/*byte pattern:*/"e8 ? ? ? ? 48 8b 5c 24 ? 48 ff c7");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nRay_Force Func is Called at: 0x%llX\n", result - moduleBase);
	Size_of_in = 5;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	uintptr_t Ray_Force = ((uintptr_t)GetDwordFromBytes(&Data[1], 1) + Size_of_in + result - moduleBase) & 0xFFFFFFF;
	printf("Ray_Force Func: 0x%llX\n", Ray_Force);



	result = scanner.scanEx(/*byte pattern:*/"E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 85 C0 74 ? 48 8B 38");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nGet_g_manager_from_component Func is Called at: 0x%llX\n", result - moduleBase);
	Size_of_in = 5;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	uintptr_t gmanager = ((uintptr_t)GetDwordFromBytes(&Data[1], 1) + Size_of_in + result - moduleBase) & 0xFFFFFF;
	printf("Get g_mamger Func: 0x%llX\n", gmanager);

	result = scanner.scanEx(/*byte pattern:*/"E8 ? ? ? ? F3 0F 10 47 ? 48 8D 4C 24");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nGet_hit_bone Func is Called at: 0x%llX\n", result - moduleBase);
	Size_of_in = 5;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	uintptr_t gethitbone = ((uintptr_t)GetDwordFromBytes(&Data[1], 1) + Size_of_in + result - moduleBase) & 0xFFFFFFF;
	printf("Get_hit_bone Func: 0x%llX\n", gethitbone);

	Size_of_in = 8;
	Data.resize(Size_of_in);

	render_outline = scanner.scanEx("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 81 ? ? ? ? 41 8B F1");
	printf("\nRender Outline (VEH HOOK ADDR):0x%llX\n", render_outline - moduleBase);
	skill_struct_check = scanner.scanEx("48 63 81 ? ? ? ? 85 C0 7E ? 4C 8B C8 45 33 C0 48 8B 81 ? ? ? ? 66 39 50 ? 74 ? 49 FF C0 48 83 C0 ? 4D 3B C1 7C ? 33 C0 C3");
	printf("skill_struct_check:0x%llX\n", skill_struct_check - moduleBase);
	fnskillstruct = scanner.scanEx("48 89 5C 24 ? 56 48 83 EC ? 33 DB 48 8B F2 66 39 5A");
	printf("fnskillstruct:0x%llX\n", fnskillstruct - moduleBase);
	camera_manager = scanner.scanEx("48 8B 0D ? ? ? ? 45 33 C0 E8 ? ? ? ? 48 8B E8 F6");
	printf("Camera_Manager(Unencrypted VM can be found here):0x%llX\n", camera_manager - moduleBase);

	result = scanner.scanEx(/*byte pattern:*/"F3 0F 10 83 ? ? ? ? F3 0F 59 05 ? ? ? ? F3 0F 10 15");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	sens_ptr = (Data[5] << 8 | Data[4]);
	printf("Sensitive Ptr:0x%llX\n", sens_ptr);

	result = scanner.scanEx(/*byte pattern:*/"E8 ? ? ? ? 48 89 83 ? ? ? ? 40 88 BB");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\n\nDecrypt Visibility Func is Called at: 0x%llX\n", result - moduleBase);
	Size_of_in = 5;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	real_vis = ((uintptr_t)GetDwordFromBytes(&Data[1], 1) + Size_of_in + result - moduleBase) & 0xFFFFFF;
	printf("Decrypt Visbility Func: 0x%llX\n", real_vis);
	SignatureScanner scannervisfn = SignatureScanner(/*process:*/hProcess, /*start address:*/real_vis + moduleBase/*,end address: (optional)*/);

	result = scannervisfn.scanEx("48 8D 05 ? ? ? ? 48 8B CB 48 8B D3 83 E1 ? 48 C1 EA ? 83 E2 ? 48 8D 14 CA 48 8B CF 48 33 0C 02 33 C0 48 33 D9 49 8B C8 48 2B CF 48 83 C1 ? 48 C1 E9 ? 49 3B F8 ");
	Size_of_in = 7;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	visread = ((uintptr_t)GetDwordFromBytes(&Data[3], 1) + Size_of_in + result - moduleBase);

	printf("Need to read for vis:0x%llX\n", visread);
	result = scannervisfn.scanEx("48 8B F8 E8 ? ? ? ? 4C 8B C0 48 B8 ? ? ? ? ? ? ? ? 48 2B D8 48 8D 05 ? ? ? ? 48 8B CB 48 8B D3 83 E1 ? 48 C1 EA ? 83 E2 ? 48 8D 14 CA 48 8B CF 48 33 0C 02 33 C0 48 33 D9 49 8B C8 48 2B CF 48 83 C1 ? 48 C1 E9 ? 49 3B F8 ");
	printf("Vis FN:0x%llX\n", result - moduleBase);
	visfn = result - moduleBase;
	SignatureScanner scannerviskey = SignatureScanner(/*process:*/hProcess, /*start address:*/result/*,end address: (optional)*/);
	result = scannerviskey.scanEx("48 B8 ? ? ? ? ? ? ? ? 48");
	int Size_of_VisKey = 10;
	std::vector<BYTE> Data_xor_key_vis;
	Data_xor_key_vis.resize(Size_of_VisKey);
	ReadProcessMemory(hProcess, (void*)(result), &Data_xor_key_vis.front(), Size_of_VisKey, NULL);
	std::cout << "Visbility Xor Key 1:0x";
	for (int i = Size_of_VisKey - 1; i >= 2; --i) {
		printf("%02X", (unsigned char)Data_xor_key_vis[i]);
	}

	result = scanner.scanEx(/*byte pattern:*/"E8 ? ? ? ? 48 33 43 ? 83 7F ? ? 7E");
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\n\nDecrypt Outline Func is Called at: 0x%llX\n", result - moduleBase);
	Size_of_in = 5;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	real_outline = ((uintptr_t)GetDwordFromBytes(&Data[1], 1) + Size_of_in + result - moduleBase) & 0xFFFFFF;
	printf("Decrypt Outline Func: 0x%llX\n", real_outline);
	SignatureScanner scanneroutfn = SignatureScanner(/*process:*/hProcess, /*start address:*/real_outline + moduleBase/*,end address: (optional)*/);
	result = scanneroutfn.scanEx("48 8D 05 ? ? ? ? 48 8B CB 48 8B D3 83 E1 ? 48 C1 EA ? 83 E2 ? 48 8D 14 CA 48 8B CF 48 33 0C 02 33 C0 48 33 D9 49 8B C8 48 2B CF 48 83 C1 ? 48 C1 E9 ? 49 3B F8 ");
	Size_of_in = 7;
	Data.resize(Size_of_in);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	outread = ((uintptr_t)GetDwordFromBytes(&Data[3], 1) + Size_of_in + result - moduleBase);
	printf("Need to read for outline:0x%llX\n", outread);
	result = scanneroutfn.scanEx("48 8B F8 E8 ? ? ? ? 4C 8B C0 48 B8 ? ? ? ? ? ? ? ? 48 2B D8 48 8D 05 ? ? ? ? 48 8B CB 48 8B D3 83 E1 ? 48 C1 EA ? 83 E2 ? 48 8D 14 CA 48 8B CF 48 33 0C 02 33 C0 48 33 D9 49 8B C8 48 2B CF 48 83 C1 ? 48 C1 E9 ? 49 3B F8 ");
	printf("Outline FN:0x%llX\n", result - moduleBase);
	std::vector<BYTE> Data_xor_key_out;
	Data_xor_key_out.resize(Size_of_VisKey);
	outfn = result - moduleBase;
	SignatureScanner scanneroutkey = SignatureScanner(/*process:*/hProcess, /*start address:*/result/*,end address: (optional)*/);
	result = scanneroutkey.scanEx("48 B8 ? ? ? ? ? ? ? ? 48");
	ReadProcessMemory(hProcess, (void*)(result), &Data_xor_key_out.front(), Size_of_VisKey, NULL);
	std::cout << "OutLine Xor Key 1:0x";
	for (int i = Size_of_VisKey - 1; i >= 2; --i) {
		printf("%02X", (unsigned char)Data_xor_key_out[i]);
	}
	printf("\n\n");


	Size_of_in = 7;//vm xor base
	Data.resize(Size_of_in);
	result = scanner.scanEx(/*byte pattern:*/"48 8B 05 ? ? ? ? 49 BE ? ? ? ? ? ? ? ? 49 33 C6 48 8B D9"); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("VMXorBase: 0x%llX", result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in);
	vmbase = result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in;
	int Size_of_XORKEY = 10;
	std::vector<BYTE> Data_xor_key;
	Data_xor_key.resize(Size_of_XORKEY);
	ReadProcessMemory(hProcess, (void*)(result + Size_of_in), &Data_xor_key.front(), Size_of_XORKEY, NULL);
	std::cout << "\nVM XOR KEY:0x";
	for (int i = Size_of_XORKEY - 1; i >= 2; --i) {
		printf("%02X", (unsigned char)Data_xor_key[i]);
	}
	VMKEY = Data_xor_key;
	//Entity admin
	Size_of_in = 7;
	Data.resize(Size_of_in);
	result = scanner.scanEx(/*byte pattern:*/"48 03 0D ?? ?? ?? ?? 74 60", 2); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nEntity Admin: 0x%llX", result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in);
	entitylist = result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in;

	//unencrypted vm
	Size_of_in = 7;
	Data.resize(Size_of_in);
	result = scanner.scanEx("48 8B 0D ? ? ? ? 45 33 C0 E8 ? ? ? ? 48 8B F0"); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nUnEncrypted VM: 0x%llX", result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in);
	vmunbase = result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in;

	//change Fov
	Size_of_in = 10;
	Data.resize(Size_of_in);
	SignatureScanner scanne2 = SignatureScanner(/*process:*/hProcess, /*start address:*/moduleBase/*,end address: (optional)*/);
	result = scanne2.scanEx("C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? C6 05 ? ? ? ? ? 48 C7 05 ? ? ? ? ? ? ? ? 48 C7 05 ? ? ? ? ? ? ? ? 48 C7 05 ? ? ? ? ? ? ? ? 48 83 C4 ? E9 ? ? ? ? CC CC CC CC CC CC CC CC CC ", 1); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nFOV changer: 0x%llX", result + (uintptr_t)GetDwordFromBytes(&Data[2], 1) - moduleBase + Size_of_in);
	fov = result + (uintptr_t)GetDwordFromBytes(&Data[2], 1) - moduleBase + Size_of_in;
	//Silent
	Size_of_in = 5;
	Data.resize(Size_of_in);
	result = scanner.scanEx("41 0F B7 4A ? 66 3B C8 7C ? B8 ? ? ? ? EB ? B8 ? ? ? ? 66 3B C8 7F ? B8 ? ? ? ? 66 41 89 42 ? 41 FF 82"); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nUser CMD: 0x%llX", result - moduleBase);
	silent = result - moduleBase;
	//Sombra Glow
	Size_of_in = 4;
	Data.resize(Size_of_in);
	result = scanner.scanEx("48 ? ? 30 80 B9 ? ? ? ? 00 48 ? ? 48 ? ? 4C ? ?"); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nSombra GLOW: 0x%llX", result - moduleBase);
	glow = result - moduleBase;

	int jumpdecide = 0;
	//GetComponent and hook key:
	Size_of_in = 2;
	Data.resize(Size_of_in);
	result = scanner.scanEx("40 53 56 57 48 83 EC ? 4C 8B ??"); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	printf("\nGet component Located: 0x%llX", result - moduleBase);
	int jumpint = 0;
	int readint = 1;
	SignatureScanner scanneget = SignatureScanner(/*process:*/hProcess, /*start address:*/result/*,end address: (optional)*/);
	while (1) {
	    jumpint = 0;
		readint = 1;
		result = scanneget.scanEx("E8 ? ? ? FE", jumpdecide);
		getkeyadd = result - moduleBase + 5;
		
		while (readint != 0) {
			ReadProcessMemory(hProcess, (void*)(result + jumpint + 5), &readint, 1, NULL);
			jumpint++;
		}
		while (readint == 0) {
			ReadProcessMemory(hProcess, (void*)(result + jumpint + 5), &readint, 1, NULL);
			jumpint++;
		}
		rip = jumpint - 1;
		if (rip < 20) break;
		else jumpdecide++;
	}
	printf("\nGet Key hooking add: 0x%llX", result - moduleBase + 5);
	printf("\nRIP+=%d", jumpint - 1);
	//HEAP MANAGER
////48 8B 0D ? ? ? ? 48 8B 89 ? ? ? ? E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 48 8B 0D ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B 1D ? ? ? ? 48 89 BC 24
	result = scanner.scanEx("e8 ? ? ? ? 4c 8b bc 24 ? ? ? ? 4c 8b b4 24 ? ? ? ? 4c 8b ac 24 ? ? ? ? 4c 8b a4 24 ? ? ? ? 48 8b b4 24 ? ? ? ? 48 8b 4d", 2); // accepts both ? and ?? wildcards, uppercase and lowercase
	Size_of_in = 7;
	Data.resize(Size_of_in);
	heap = 0;
	while (!(heap > 0x3000000 && heap < 0x4000000)) {
		SignatureScanner scanneheap = SignatureScanner(/*process:*/hProcess, /*start address:*/result/*,end address: (optional)*/);
		result = scanneheap.scanEx("48 8B ? ? ? ? ?"); // accepts both ? and ?? wildcards, uppercase and lowercase
		ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
		heap = result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in;
	}
	printf("\nHEAP Manager Located: 0x%llX", result - moduleBase);
	printf("\nHEAP Manager: 0x%llX", heap);
	SignatureScanner scanneheap = SignatureScanner(/*process:*/hProcess, /*start address:*/result/*,end address: (optional)*/);
	result = scanneheap.scanEx("48 ? 1D ? ? ? ?"); // accepts both ? and ?? wildcards, uppercase and lowercase
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), Size_of_in, NULL);
	heapvar = result + (uintptr_t)GetDwordFromBytes(&Data[3], 1) - moduleBase + Size_of_in;
	printf("\nHEAP Manager Var: 0x%llX", heapvar);

	result = scanneheap.scanEx("48 ? ? ? ? ? ? ? ? ? 48 ?"); // accepts both ? and ?? wildcards, uppercase and lowercase
	int size_of_heap_key = 10;
	Data.resize(size_of_heap_key);
	ReadProcessMemory(hProcess, (void*)(result), &Data.front(), size_of_heap_key, NULL);
	printf("\nHEAP Manager Key Addr: 0x%llX\nKey:0x", result - moduleBase);
	for (int i = size_of_heap_key - 1; i >= 2; --i) {
		printf("%02X", (unsigned char)Data[i]);
	}
	HEAPKEY = Data;


	printf("\n\nstatic constexpr auto Address_viewmatrix_base = 0x%llX;", vmbase);
	printf("\nstatic constexpr auto Address_viewmatrix_base_test = 0x%llX;", vmunbase);
	printf("\nstatic constexpr auto Address_entity_base = 0x%llX;", entitylist);
	printf("\nstatic constexpr auto offset_viewmatrix_ptr = 0x7E0;");
	printf("\nstatic constexpr auto offset_viewmatrix_xor_key = 0x");
	for (int i = 9; i >= 2; --i) {
		printf("%02X", (unsigned char)(VMKEY[i]));
	}

	printf(";\nstatic constexpr auto HeapManager = 0x%llX;", heap);
	printf("\nstatic constexpr auto HeapManager_Var = 0x%llX;", heapvar);
	printf("\nstatic constexpr auto HeapManager_Key = 0x");
	for (int i = 9; i >= 2; --i) {
		printf("%02X", (unsigned char)(HEAPKEY[i]));
	}
	printf(";\nstatic constexpr auto HeapManager_Pointer = 0x160;");
	printf("\nstatic constexpr auto changefov = 0x%llX;", fov);
	printf("\nstatic constexpr auto GetKeyAdd = 0x%llX;", getkeyadd);
	printf("\nstatic constexpr auto GetKeyAddRIP = 0x%llX;", rip);
	printf("\nstatic constexpr auto GlowESP = 0x%llX;", glow);
	printf("\nstatic constexpr auto Silent = 0x%llX;", silent);
	printf("\nstatic constexpr auto SensitivePtr = 0x%llX;", sens_ptr);
	printf("\nstatic constexpr auto VisFN = 0x%llX;", visfn);
	printf("\nstatic constexpr auto VisRead = 0x%llX;", visread);
	printf("\nstatic constexpr auto Vis_Key = 0x");
	for (int i = 9; i >= 2; --i) {
		printf("%02X", (unsigned char)(Data_xor_key_vis[i]));
	}
	printf(";\n\nstatic constexpr auto OutlineFN = 0x%llX;", outfn);
	printf("\nstatic constexpr auto OutlineRead = 0x%llX;", outread);
	printf("\nstatic constexpr auto OutLine_Key = 0x");
	for (int i = 9; i >= 2; --i) {
		printf("%02X", (unsigned char)(Data_xor_key_out[i]));
	}
	printf(";\n");
	system("pause");
	return 0;
}
