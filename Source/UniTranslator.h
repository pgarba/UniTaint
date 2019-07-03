#pragma once

#include <sstream> 
#include <set>
#include <map>
#include <string>
#include <iostream>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <keystone/keystone.h>

#include "CS_Reg_Mapping.h"

class UniTranslator {
public:
	UniTranslator(uc_engine *uc, uint64_t RSP_Base, uint64_t EntryPointVA) {
		this->uc = uc;
		this->CurrentSlot = 0;
		this->RSP_Base = RSP_Base;
	};

	~UniTranslator() {
		this->uc = nullptr;
		this->printTranslation();
	}

	void printTranslation() {
		// Create Slots
		for (int i = 0; i < this->CurrentSlot; i++) {
			printf("uint64_t S_%d;\n", i);
		}
		printf("\n");

		std::cout << this->LoggedInstructions;
	}

	uint64_t getAbsoluteAddress(x86_op_mem &Mem) {
		uint64_t Addr = 0;
		if (Mem.base != X86_REG_INVALID) {
			uc_reg_read(uc, Mem.base, &Addr);
		}

		if (Mem.index != X86_REG_INVALID) {
			uint64_t Index;
			uc_reg_read(uc, Mem.index, &Index);
			Addr = Addr + Index * Mem.scale;
		}

		Addr += Mem.disp;

		return Addr;
	}

	uint64_t getOperandValue(cs_x86_op &Op, bool Read = false) {
		uint64_t V = 0;

		switch (Op.type) {
		case CS_OP_REG: {
			int RReg = Op.reg;
			uc_reg_read(uc, RReg, &V);
		}
		break;
		case CS_OP_MEM: {
			V = this->getAbsoluteAddress(Op.mem);
			if (Read) {
				uc_mem_read(uc, V, &V, 8);
			}
		}
		break;
		case CS_OPT_INVALID: {
			V = 0xDEADBEEF;
		}
		break;
		default:
			assert("Unknown operand type!\n");
		}

		return V;
	}

	uint64_t getRSP() {
		uint64_t V = 0;
		uc_reg_read(uc, UC_X86_REG_RSP, &V);

		return V;
	}

	std::string getOperandAsString(cs_x86_op &Op, char TaintType = 'N') {
		switch (Op.type) {
		case CS_OP_REG: {
			if (TaintType == 'C') {
				uint64_t V;
				uc_reg_read(this->uc, Op.reg, &V);
				return std::to_string(V);
			}
			else {
				auto &StrReg = CS_x86_Reg_Map[Op.reg];
				return StrReg;
			}
		}
		break;
		case CS_OP_MEM: {
			auto Addr = this->getAbsoluteAddress(Op.mem);
			std::string StrAddr = "S_" + std::to_string(getSlot(Addr));
			return StrAddr;
		}
		break;
		default:
			assert("Unknown operand type!\n");
		}

		return "";
	}

	std::string getOperandAsStringRemill(cs_x86_op &Op) {
		switch (Op.type) {
		case CS_OP_REG: {
			auto &StrReg = CS_x86_Reg_Map[Op.reg];
			return StrReg;
		}
						break;
		case CS_OP_MEM: {
			auto Addr = this->getAbsoluteAddress(Op.mem);

			Addr = RSP_Base - Addr;

			//std::string StrAddr = "qword ptr [" + std::to_string(getSlot(Addr) * 8) + "] ";
			std::string StrAddr = "qword ptr [RSP - " + std::to_string(Addr) + "] ";
			return StrAddr;
		}
						break;
		default:
			assert("Unknown operand type!\n");
		}
	}

	std::string rewriteInstruction(cs_insn &Inst) {
		std::string NewInst = Inst.mnemonic;
		if (Inst.detail->x86.op_count > 0) {
			NewInst += " ";
			NewInst += getOperandAsStringRemill(Inst.detail->x86.operands[0]);
		}

		if (Inst.detail->x86.op_count > 1) {
			NewInst += " , ";
			NewInst += getOperandAsStringRemill(Inst.detail->x86.operands[1]);
		}

		// assemble
		ks_engine *ks;
		ks_err err;
		size_t size;
		unsigned char *encode;
		size_t count;

		err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);

		ks_asm(ks, NewInst.c_str(), 0, &encode, &size, &count);

		// NOTE: free encode after usage to avoid leaking memory
		ks_free(encode);

		// close Keystone instance when done
		ks_close(ks);

		return NewInst;
	}

	void translateInstruction(cs_insn &Inst, std::vector<char> &TT) {
		//LLVM test
		//translateInstructionLLVM(Inst);

		return;

		// We need to do it a little bit smarter ;)
		std::string NInst = rewriteInstruction(Inst);

		std::stringstream SS;

		cs_detail *Detail = Inst.detail;
		cs_x86 &X86 = Detail->x86;
		int OpcodeLen = Inst.size;

		std::string Op = Inst.mnemonic;
		if (Op == "push") {
			uint64_t RSP = getRSP();
			uint64_t Slot = getSlot(RSP - 8);

			SS << "S_" << Slot << " = " << getOperandAsString(X86.operands[0], TT[0]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else if (Op == "pop") {
			uint64_t RSP = getRSP();
			int64_t Slot = getSlot(RSP);

			SS << getOperandAsString(X86.operands[0]) << " = " << "S_" << Slot << ";\n";
			this->LoggedInstructions += SS.str();
		} 
		else if (Op == "mov") {
			SS << getOperandAsString(X86.operands[0]) << " = " << getOperandAsString(X86.operands[1], TT[1]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else if (Op == "imul") {
			// needs more work
			SS << "rax = rax * " << getOperandAsString(X86.operands[0], TT[0]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else if (Op == "not") {
			SS << getOperandAsString(X86.operands[0]) << " = " << "~" << getOperandAsString(X86.operands[0], TT[0]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else if (Op == "or") {
			SS << getOperandAsString(X86.operands[0]) << " = " << getOperandAsString(X86.operands[0], TT[0]) << " | " << getOperandAsString(X86.operands[1], TT[1]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else if (Op == "and") {
			SS << getOperandAsString(X86.operands[0]) << " = " << getOperandAsString(X86.operands[0], TT[0]) << " & " << getOperandAsString(X86.operands[1], TT[1]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else if (Op == "add") {
			SS << getOperandAsString(X86.operands[0]) << " = " << getOperandAsString(X86.operands[0], TT[0]) << " + " << getOperandAsString(X86.operands[1], TT[1]) << ";\n";
			this->LoggedInstructions += SS.str();
		}
		else {
			// Not implemented so far
			int j = 2;
			printf("// Not implemented opcode : %s\n", Op.c_str());
		}
	}

	int getSlot(uint64_t VA) {
		auto S = Slots.find(VA);
		if (S != Slots.end()) {
			return SlotMap[VA];
		}

		Slots.insert(VA);
		SlotMap[VA] = CurrentSlot;

		return CurrentSlot++;
	}

	llvm::Value *getSlotRemill(uint64_t VA) {
		auto S = Slots.find(VA);
		if (S != Slots.end()) {
			return SlotMapLLVM[VA];
		}

		Slots.insert(VA);
		SlotMap[VA] = CurrentSlot;
		CurrentSlot++;

		return SlotMapLLVM[VA];
	}

private:
	uc_engine *uc;

	uint64_t RSP_Base;

	int CurrentSlot;
	std::set<uint64_t> Slots;
	std::map<uint64_t, int> SlotMap;
	std::map<uint64_t, llvm::Value *> SlotMapLLVM;

	std::string LoggedInstructions;	
};