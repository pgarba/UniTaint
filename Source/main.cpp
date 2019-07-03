#include <stdint.h>

#include <unicorn/unicorn.h>

#include "UniTaint.h"
#include "UniTranslator.h"

using namespace Uni;

#include <Windows.h>

typedef struct {
	uint64_t EntryPoint;
	uint64_t ImageBase;
	uint64_t ImageSize;
	uint64_t ImportTableVA;
	uint8_t *VirtualImage;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS64 NTHeader;
	std::vector<PIMAGE_SECTION_HEADER> Sections;
	uint8_t *Buffer;
} *PSPEImage, SPEImage;

SPEImage PEImage;

bool ParsePE64(char *FilePath) {
	FILE *fp = fopen(FilePath, "rb");
	if (!fp) {
		printf("Could not open file %s !\n", FilePath);
		return 0;
	}

	// Get FileSize
	fseek(fp, 0, SEEK_END);
	size_t FileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Alloc Mem
	uint8_t *FileMem = (uint8_t *)calloc(1, FileSize);

	// Read and close
	fread(FileMem, 1, FileSize, fp);
	fclose(fp);

	PEImage.DosHeader = (PIMAGE_DOS_HEADER)FileMem;
	PEImage.NTHeader = (PIMAGE_NT_HEADERS64)(((BYTE *)PEImage.DosHeader) + (PEImage.DosHeader->e_lfanew));

	// Get ImageBase	
	PEImage.EntryPoint = PEImage.NTHeader->OptionalHeader.AddressOfEntryPoint;

	//Fill return struct
	PEImage.ImageBase = PEImage.NTHeader->OptionalHeader.ImageBase;
	PEImage.ImageSize = PEImage.NTHeader->OptionalHeader.SizeOfImage;
	PEImage.EntryPoint = PEImage.EntryPoint + PEImage.ImageBase;
	PEImage.ImportTableVA = PEImage.NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// Check if we can relocate the image
	uint64_t PreferredAddress = 0;
	if ((PEImage.NTHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
		//Cant't load without this
		printf("Image has no dynamic base! Trying to load at the specific base\n");
		PreferredAddress = PEImage.NTHeader->OptionalHeader.ImageBase;
	}

	// Allocate Virtual Image Read/Write only to raise an exception if a thread/code gets started and we miss to catch it
	uint8_t *VImage = (uint8_t *)VirtualAlloc((void *)PreferredAddress, PEImage.NTHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!VImage) {
		printf("Could not allocate memory @ %llX\n", PreferredAddress);
		return false;
	}
	memset(VImage, 0, PEImage.NTHeader->OptionalHeader.SizeOfImage);
	PEImage.VirtualImage = VImage;

	// Parse the sections and load image into memory	
	PIMAGE_SECTION_HEADER psectionheader = (PIMAGE_SECTION_HEADER)(PEImage.NTHeader + 1);
	for (int i = 0; i < PEImage.NTHeader->FileHeader.NumberOfSections; i++) {
		uint64_t SectionVA = psectionheader->VirtualAddress;
		uint64_t SectionSize = psectionheader->Misc.VirtualSize;
		uint64_t RawOffset = psectionheader->PointerToRawData;
		uint64_t RawSize = psectionheader->SizeOfRawData;

		//printf("%s Page %08llX %08llX\n", psectionheader->Name, SectionVA, SectionSize);

		// Add image 
		PEImage.Sections.push_back(psectionheader);

		//copy information
		memcpy(VImage + SectionVA, FileMem + RawOffset, (size_t)RawSize);

		//Copy the header
		if (i == 0) {
			memcpy(VImage, FileMem, (size_t)RawOffset);
		}

		psectionheader++;
	}

	return true;
}

uint64_t RawToVA(uint64_t RawAddress) {
	for (auto S : PEImage.Sections) {
		if (RawAddress >= S->PointerToRawData && RawAddress < (S->PointerToRawData + S->SizeOfRawData)) {
			return RawAddress - S->PointerToRawData + S->VirtualAddress;
		}
	}

	std::exception("RawAddress not found!");
}

uint64_t VaToRaw(uint64_t VA) {
	for (auto S : PEImage.Sections) {
		if (VA >= S->VirtualAddress && VA < (S->VirtualAddress + S->Misc.VirtualSize)) {
			return VA - S->VirtualAddress + S->PointerToRawData;
		}
	}

	std::exception("VA not found!");
}


// callback for tracing instruction
bool hook_Segment_error(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	switch (type) {
	case UC_MEM_READ_UNMAPPED:
	case UC_MEM_WRITE_UNMAPPED:
	{
		//Like in code
		uint64_t RIP;
		uc_reg_read(uc, UC_X86_REG_RIP, &RIP);

		uint64_t RSP;
		uc_reg_read(uc, UC_X86_REG_RIP, &RSP);

		// Disable logging
		printf("Missing memory @ 0x%08llX [%08llX] RSP[%08llX]\n", RIP, address, *(uint64_t *) RSP);
		
		//printX64Regs(uc);		

		return true;
	}
	case UC_MEM_FETCH_UNMAPPED:
	{
		uint64_t RIP;
		uc_reg_read(uc, UC_X86_REG_RIP, &RIP);

		uint64_t RSP;
		uc_reg_read(uc, UC_X86_REG_RSP, &RSP);

		printf("0x%08llX External code: Return to 0x%08llX\n", RIP, *(uint64_t *)RSP);		

		return true;
	}
	default:
		// return false to indicate we want to stop emulation
		printf("Failed hook_Segment_error!\n");
		return false;
	}
}


typedef struct {
	uint64_t VA;
	uint8_t Opcode[16];
} Entry;

int main(int argc, char **argv) {
	uc_engine *uc;
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
	}

	// RSP Stack base
	uint64_t CurrentVA = 0x146EA48E5; // PEImage.EntryPoint;
	uint64_t OriginalRSP = 0x5000;

	// init UniTaint
	UniTaint UT(uc, OriginalRSP, CurrentVA);

	// map test
	/*
	uint64_t Code = 0x1000;
	err = uc_mem_map(uc, Code, 0x1000, UC_PROT_ALL);
	err = uc_mem_write(uc, Code, Test1, sizeof(Test1));
	*/
	// Parse binary
	ParsePE64(argv[1]);

	// map pe into unicorn
	err = uc_mem_map(uc, (uint64_t)PEImage.ImageBase, (size_t)PEImage.ImageSize, UC_PROT_ALL);
	err = uc_mem_write(uc, PEImage.ImageBase, PEImage.VirtualImage, PEImage.ImageSize);
	if (err) {
		printf("MapPEIntoUnicorn failed! %i\n", err);
		return false;
	}

	// Setup hooks
	uc_hook SegmentError;
	uc_hook Interrupt;

	// tracing all instruction by having @begin > @end
	err = uc_hook_add(uc, &SegmentError, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, (void *)hook_Segment_error, 0, 1, 0);
	if (err) {
		printf("Failed on uc_hook_add() with error returned: %s\n", uc_strerror(err));
	}

	// Taint registers
	UT.addEPTaint(X86_REG_RAX);
	UT.addEPTaint(X86_REG_RBX);
	UT.addEPTaint(X86_REG_RCX);
	UT.addEPTaint(X86_REG_RDX);
	UT.addEPTaint(X86_REG_R8);	
	UT.addEPTaint(X86_REG_RSI);
	UT.addEPTaint(X86_REG_RDI);
	UT.addEPTaint(X86_REG_RBP);
	UT.addEPTaint(X86_REG_R8);
	UT.addEPTaint(X86_REG_R9);
	UT.addEPTaint(X86_REG_R10);
	UT.addEPTaint(X86_REG_R11);
	UT.addEPTaint(X86_REG_R12);
	UT.addEPTaint(X86_REG_R13);
	UT.addEPTaint(X86_REG_R14);
	UT.addEPTaint(X86_REG_R15);	
	
	// Create stack
	err = uc_mem_map(uc, OriginalRSP-0x1000, 0x1000, UC_PROT_ALL);

	uint64_t CurrentRSP = OriginalRSP;
	uc_reg_write(uc, UC_X86_REG_RSP, &CurrentRSP);

	uint64_t RCX = 0x1111111111111111;
	uint64_t RDX = 0x2222222222221111; 
	uint64_t R8 = 0x777;
	uint64_t RAX = 0;
	uc_reg_write(uc, UC_X86_REG_RCX, &RCX);
	uc_reg_write(uc, UC_X86_REG_RDX, &RDX);
	uc_reg_write(uc, UC_X86_REG_R8, &R8);

	// Test
	/*
	uint8_t RTest[] = { 0x48, 0xC7, 0xC0, 0x11, 0x11, 0x11, 0x11, 0x48, 0xC7, 0xC0, 0x22, 0x22, 0x22, 0x22 };
	UT.translateInstructionRemill(CurrentVA, RTest, 16, 1);
	UT.translateInstructionRemill(CurrentVA, RTest + 7, 16, 1);
	*/
	std::vector<Entry> TraceLog;	

	do {
		uint8_t Opcode[16];
		uc_mem_read(uc, CurrentVA, Opcode, 16);
	
		Entry E;
		E.VA = CurrentVA;
		memcpy(E.Opcode, Opcode, 16);
		TraceLog.push_back(E);		

		//UT.processInstructions(uc, CurrentVA, Opcode, 16, 1, CurrentRSP);
		UT.translateInstructionRemill(CurrentVA, Opcode, 16, 1);
	
		err = uc_emu_start(uc, CurrentVA, -1, 0, 1);

		uc_reg_read(uc, UC_X86_REG_RIP, &CurrentVA);
		uc_reg_read(uc, UC_X86_REG_RSP, &CurrentRSP);
	} while (CurrentVA != -1 && err == UC_ERR_OK);

	// Print if there was an error
	/*
	if (err != UC_ERR_OK) {
		std::cout << "UC Error: " << uc_strerror(err) << "\n";
		return 1;
	}
	*/

	// Write log file
	FILE *fp = fopen("trace.bin", "wb");
	uint64_t S = TraceLog.size();
	fwrite(&S, sizeof(uint64_t), 1, fp);

	for (auto &E : TraceLog) {
		fwrite(&E, sizeof(Entry), 1, fp);
	}

	fclose(fp);

	uc_reg_read(uc, UC_X86_REG_RAX, &RAX);
	printf("Result (RAX) = %llX\n", RAX);
	uc_reg_read(uc, UC_X86_REG_R8, &RAX);
	printf("Result (R8)  = %llX\n", RAX);

	// Finish llvm translation
	UT.dumpLLVMTranslation("VMP_llvm.ll");

	return 0;
}