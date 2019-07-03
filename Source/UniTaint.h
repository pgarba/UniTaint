#pragma once
#include <vector>
#include <string>
#include <assert.h>
#include <set>
#include <map>

#include <capstone/capstone.h>
#include <beaengine/BeaEngine.h>

#include "UniTranslator.h"


namespace Uni {

	int X86Regs[][5] = {
		{X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AH, X86_REG_AL},
		{X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BH, X86_REG_BL},
		{X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CH, X86_REG_CL},
		{X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DH, X86_REG_DL},
		{X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL, 0},
		{X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL, 0},
		{X86_REG_RBP, X86_REG_EBP, X86_REG_BP, 0, 0},
		{X86_REG_RSP, X86_REG_ESP, X86_REG_SP, 0, 0},
		{X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_R8B, 0},
		{X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_R9B, 0},
		{X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B, 0},
		{X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B, 0},
		{X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B, 0},
		{X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B, 0},
		{X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B, 0},
		{X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B, 0},
	};

	enum TType {
		Reg = 1,
		Memory = 2
	};

	class TValue {
	public:
		virtual TType getType() {
			return Type;
		}

		TType Type;
	};

	class TReg : TValue {
	public:
		TReg(int Register) {
			this->Register = Register;
			this->Type = TType::Reg;
		}

		int getRegister() {
			return Register;
		}
	private:
		int Register;
	};

	class TMemory : TValue {
	public:
		TMemory(uint64_t Offset) {
			this->Offset = Offset;
			this->Type = TType::Memory;
		}

		uint64_t getOffset() {
			return Offset;
		}
	private:
		uint64_t Offset;
	};

	class UniTaint {
	public:
		UniTaint(uc_engine *uc, uint64_t RSP_Base, uint64_t EntryPointVA) : UT(uc, RSP_Base, EntryPointVA) {
			this->uc = uc;
			TaintAll = false;

			cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &this->HCapstone);
			if (err) {
				printf("Failed on cs_open() with error returned: %u\n", err);
				exit(0);
			}

			// Set detail option
			cs_option(this->HCapstone, CS_OPT_DETAIL, CS_OPT_ON);
		};
		~UniTaint() {};

		bool isTaintedReg(int Reg) {
			if (TaintAll == true) {
				return true;
			}
			for (auto Iter = TaintedValues.begin(); Iter != TaintedValues.end(); ++Iter) {
				if ((*Iter)->getType() == TType::Reg) {
					TReg *R = (TReg *)*Iter;
					if (R->getRegister() == Reg) {
						return true;
					}
				}
			}
			return false;
		}

		bool isTaintedMemory(uint64_t Offset) {
			if (TaintAll == true) {
				return true;
			}
			for (auto Iter = TaintedValues.begin(); Iter != TaintedValues.end(); ++Iter) {
				if ((*Iter)->getType() == TType::Memory) {
					TMemory *M = (TMemory *)*Iter;
					if (M->getOffset() == Offset) {
						return true;
					}
				}
			}
			return false;
		}

		/*
		int getFullReg(int Reg) {
			// Some test
			return Reg;

			int FullReg = 0;
			for (int i = 0; i < 16; i++) {
				for (int j = 0; j < 5; j++) {
					if (X86Regs[i][j] == 0)
						break;

					if (X86Regs[i][j] == Reg)
						return X86Regs[i][0];
				}
			}

			assert(FullReg == 0 && "Full register not found!");
		}
		*/

		void addReg(int Reg) {
			if (this->isTaintedReg(Reg) == false) {
				TaintedValues.push_back((TValue *) new TReg(Reg));
			}
		}

		void removeReg(int Reg) {
			for (auto Iter = TaintedValues.begin(); Iter != TaintedValues.end(); ++Iter) {
				if ((*Iter)->getType() == TType::Reg) {
					TReg *R = (TReg *)*Iter;
					if (R->getRegister() == Reg) {
						TaintedValues.erase(Iter);
						return;
					}
				}
			}
		}


		void addMemory(uint64_t Offset) {
			if (this->isTaintedMemory(Offset) == false) {
				TaintedValues.push_back((TValue *) new TMemory(Offset));
			}
		}

		void removeMemory(uint64_t Offset) {
			for (auto Iter = TaintedValues.begin(); Iter != TaintedValues.end(); ++Iter) {
				if ((*Iter)->getType() == TType::Memory) {
					TMemory *M = (TMemory *)*Iter;
					if (M->getOffset() == Offset) {
						TaintedValues.erase(Iter);
						return;
					}
				}
			}
		}

		void addEPTaint(int Reg) {
			if (this->isTaintedReg(Reg) == false) {
				TaintedValues.push_back((TValue *) new TReg(Reg));
				EPTaintedValues.insert(Reg);
			}
		}

		void setTaintAllMode() {
			this->TaintAll = true;
		}

		void setTaint(uc_engine *uc, cs_x86_op &Op) {
			switch (Op.type) {
			case CS_OP_REG: {
				this->addReg(Op.reg);
			}
			break;
			case CS_OP_MEM: {
				uint64_t MemPtr = this->getAbsoluteAddress(uc, Op.mem);
				this->addMemory(MemPtr);
			}
			break;
			default:
				assert("setTaint Unknown type!\n");
			}
		}

		void removeTaint(uc_engine *uc, cs_x86_op &Op) {
			switch (Op.type) {
			case CS_OP_REG: {
				this->removeReg(Op.reg);
			}
			break;
			case CS_OP_MEM: {
				uint64_t MemPtr = this->getAbsoluteAddress(uc, Op.mem);
					this->removeMemory(MemPtr);
			}
			break;
			default:
				assert("setTaint Unknown type!\n");
			}
		}

		bool isPush(cs_insn &Instruction) {
			if (!strncmp(Instruction.mnemonic, "push", 4)) {
				return true;
			}
			return false;
		}

		bool isPop(cs_insn &Instruction) {
			if (!strncmp(Instruction.mnemonic, "pop", 3)) {
				return true;
			}
			return false;
		}

		bool isRead(cs_x86_op &Op) {
			return Op.access & CS_AC_READ;
		}

		bool isWrite(cs_x86_op &Op) {
			return Op.access & CS_AC_WRITE;
		}

		bool isPushed(int Reg) {
			// Check if reg is tainted at the EP
			if (EPTaintedValues.find(Reg) == EPTaintedValues.end()) {
				// Then always ok to use it
				return true;
			}

			if (PushedRegs.find(Reg) == PushedRegs.end()) {
				return false;
			}

			return true;
		}

		bool isEPTaintedSlot(uint64_t Addr) {
			if (this->EPTaintedValuesSlots.find(Addr) != this->EPTaintedValuesSlots.end())
				return true;

			return false;
		}

		int isValidOperation(DISASM &pDisAsm, bool AllowData = false) {
			if (pDisAsm.Instruction.Category | GENERAL_PURPOSE_INSTRUCTION) {
				int Cat = pDisAsm.Instruction.Category & 0xFFFF;
				if (Cat == DATA_TRANSFER) {
					if (AllowData)
						return 1;
					return 0;
				}
			
				if (Cat == ARITHMETIC_INSTRUCTION)
					return 1;
				if (Cat == LOGICAL_INSTRUCTION)
					return 1;
				if (Cat == SHIFT_ROTATE)
					return 1;
				if (Cat == BIT_UInt8)
					return 2;
				if (Cat == CONTROL_TRANSFER)
					return 1;
				if (Cat == STRING_INSTRUCTION)
					return 1;

				assert("Not handled Instructio Catagory!");
			}

			return false;
		}

		uint64_t getAbsoluteAddress(uc_engine *uc, x86_op_mem &Mem) {
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

		uint64_t getOperandValue(uc_engine *uc, cs_x86_op &Op, bool Read=false) {
			uint64_t V = 0;

			switch (Op.type) {
			case CS_OP_REG: {
				uc_reg_read(uc, Op.reg, &V);
			}
			break;
			case CS_OP_MEM: {
				V = this->getAbsoluteAddress(uc, Op.mem);
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

		std::vector<char> getTaintType(cs_x86_op *Ops, int Count) {
			std::vector<char> TaintType;

			for (int i = 0; i < Count; i++) {
				switch (Ops[i].type) {
				case CS_OP_REG: {
					if (isTaintedReg(Ops[i].reg)) {
						// Tainted reg
						TaintType.push_back('T');
					} else {
						// Const
						TaintType.push_back('C');
					}
				}
				break;
				case CS_OP_MEM: {
					uint64_t V = this->getAbsoluteAddress(uc, Ops[i].mem);
					if (isTaintedMemory(V)) {
						TaintType.push_back('T');
					}
					else {
						TaintType.push_back('C');
					}
				}
				break;
				default:
					TaintType.push_back('N');
				}
			}

			return TaintType;
		}

		void translateInstructionRemill(uint64_t Address, const uint8_t *Code, int Size, size_t Count) {
			cs_insn *Instructions;
			int count = cs_disasm(this->HCapstone, Code, Size, Address, 1, &Instructions);

			this->UT.translateInstructionLLVM(Instructions[0]);

			// Clean up
			if (count) {
				cs_free(Instructions, count);
			}
		}

		void processInstructions(uc_engine *uc, uint64_t Address, const uint8_t *Code, int Size, size_t Count, uint64_t RSP) {
			cs_insn *Instructions;
			size_t next_ins = 0;

			//capstone
			int count = cs_disasm(this->HCapstone, Code, Size, Address, 1, &Instructions);

			//BEA
			DISASM BeaIns;
			memset(&BeaIns, 0, sizeof(DISASM));

			BeaIns.Archi = 64;
			BeaIns.EIP = (UIntPtr) Code;
			BeaIns.VirtualAddr = Address;
			int OpLen = Disasm(&BeaIns);

			
			cs_insn &Ins = Instructions[0];
			cs_detail *Detail = Ins.detail;
			cs_x86 &X86 = Detail->x86;
			int OpcodeLen = Ins.size;
			bool Handled = false;


			//printf("%08llX: %s %s // RSP %X 0: %llX 1: %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP, getOperandValue(uc, X86.operands[0]), getOperandValue(uc, X86.operands[1]));

			// Handle push / pop first
			if (isPush(Ins)) {
				switch (X86.operands[0].type) {
				case CS_OP_REG: {
					int RReg = X86.operands[0].reg;
					if (this->isTaintedReg(RReg)) {
						this->addMemory(RSP - 8);
						printf("%08llX: T %s %s // %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP - 8);

						// Translate
						auto TT = getTaintType(X86.operands, X86.op_count);
						this->UT.translateInstruction(Ins, TT);

						this->PushedRegs.insert(RReg);
						this->EPTaintedValuesSlots.insert(RSP - 8);

						// Test: Remove taint on register after push
						this->removeReg(RReg);
					}
					else {
						// Check if memory is tainted
						if (this->isTaintedMemory(RSP - 8)) {
							this->removeMemory(RSP - 8);
						}
					}
					Handled = true;
				}
					break;
				case CS_OP_MEM: {
					int64_t MemPtr = X86.operands[0].mem.disp;
					if (this->isTaintedMemory(MemPtr)) {
						this->addMemory(RSP - 8);
						printf("%08llX: T %s %s //%X\n", Address, Ins.mnemonic, Ins.op_str, RSP - 8);

						// Translate
						auto TT = getTaintType(X86.operands, X86.op_count);
						this->UT.translateInstruction(Ins, TT);

					} else {
						// Check if memory is tainted
						if (this->isTaintedMemory(RSP - 8)) {
							this->removeMemory(RSP - 8);
						}
					}
					Handled = true;
				}
					break;
				}
			}

			if (isPop(Ins)) {
				switch (X86.operands[0].type) {
				case CS_OP_REG: {
					int RReg = X86.operands[0].reg;
					if (this->isTaintedMemory(RSP)) {
						this->addReg(RReg);

						uint64_t V = 0;
						uc_mem_read(uc, RSP, &V, 8);
						printf("%08llX: T %s %s //%X V: %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP, V);

						// Translate
						auto TT = getTaintType(X86.operands, X86.op_count);
						this->UT.translateInstruction(Ins, TT);

						// Test: Remove taint on memory after pop
						this->removeMemory(RSP);
					} else if (this->isTaintedReg(RReg)) {
						// Check if reg is tainted and remove taint
						this->removeReg(RReg);
					}
					// Mark as handled
					Handled = true;
				}
					break;
				case CS_OP_MEM: {
					uint64_t Addr = this->getAbsoluteAddress(uc, X86.operands[0].mem);
					if (this->isTaintedMemory(RSP)) {
						// Remove taint on RSP and taint dest
						printf("%08llX: T %s %s // %X %X\n", Address, Ins.mnemonic, Ins.op_str, RSP, Addr);

						// Translate
						auto TT = getTaintType(X86.operands, X86.op_count);
						this->UT.translateInstruction(Ins, TT);

						this->removeMemory(RSP);
						this->addMemory(Addr);
					} else if (this->isTaintedMemory(Addr)) {
						// Unknown SRC so remove taint on Addr
						this->removeMemory(Addr);
					}
					Handled = true;
				} 
					break;
				}
			}

			// Check if operands are tainted
			for (int i = 0; i < X86.op_count; i++) {
				// If (push/pop/pushfq/popfq) then its already handled
				if (Handled)
					break;

				// Parse operands
				switch (X86.operands[i].type) {
				case CS_OP_REG:
				{
					int RReg = X86.operands[i].reg;
					uint64_t RValue = 0;
					uc_reg_read(uc, RReg, &RValue);
					if (this->isPushed(RReg) && this->isTaintedReg(RReg)) {
						if (isWrite(X86.operands[i])) {
							// Check if this is an arithmetic operation 
							int VOPType = isValidOperation(BeaIns);
							if (VOPType == 1) {
								printf("%08llX: T %s %s // RSP %X 0: %llX 1: %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP, getOperandValue(uc, X86.operands[0]), getOperandValue(uc, X86.operands[1]));

								// Translate
								auto TT = getTaintType(X86.operands, X86.op_count);
								this->UT.translateInstruction(Ins, TT);

								Handled = true;
								break;
							}
							else if (VOPType == 2) {
								// Ignore for now ... (TODO)
								// No cases where this instructions were needed so far
							} else {
								// else untaint
								this->removeReg(RReg);
								break;
							}
						}
						else if (isRead(X86.operands[i])) {
							int VOpType = isValidOperation(BeaIns, true);
							if (VOpType == 1) {
								// then we are ok
								printf("%08llX: T %s %s // RSP %X 0: %llX 1: %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP, getOperandValue(uc, X86.operands[0]), getOperandValue(uc, X86.operands[1]));

								// Translate
								auto TT = getTaintType(X86.operands, X86.op_count);
								this->UT.translateInstruction(Ins, TT);

								// taint the destination
								this->setTaint(uc, X86.operands[0]);

								// Test: remove taint on stored reg in mem
								if (X86.operands[0].type == CS_OP_MEM) {
									this->removeReg(RReg);
								}
							}
							else if (VOpType == 2) {
								// Ignore
							} else {
								// untaint
								this->removeReg(RReg);
							}
							Handled = true;
							break;
						}
					}
				}
				break;
				case CS_OP_MEM:
				{
					uint64_t MemPtr = this->getAbsoluteAddress(uc, X86.operands[i].mem);
					if (this->isTaintedMemory(MemPtr)) {
						// ReadMem
						uint64_t Value = 0;
						uc_mem_read(uc, MemPtr, &Value, 8);

						// Memory is the destination => write
						if (this->isWrite(X86.operands[i])) {
							int RReg = X86.operands[1].reg;
							uint64_t RValue = 0;
							uc_reg_read(uc, RReg, &RValue);

							// Check if source is tainted
							if (this->isTaintedReg(RReg)) {
								// Log instruction
								printf("%08llX: T %s %s // RSP %X 0: %llX 1: %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP, getOperandValue(uc, X86.operands[0]), getOperandValue(uc, X86.operands[1]));

								// Translate
								auto TT = getTaintType(X86.operands, X86.op_count);
								this->UT.translateInstruction(Ins, TT);

								// Todo:
								// We assume that this is a store and the reg is not used anymore after that ...
								this->removeReg(RReg);
							}
							else {
								// unknown reg
								// remove taint on memory slot
								this->removeMemory(MemPtr);
							}
					
							// Remove taint on Reg
							// strange disabled for now
							//this->removeReg(RReg);
						}
						else { // must be a read
							// Log instruction
							printf("%08llX: T %s %s // RSP %X 0: %llX 1: %llX\n", Address, Ins.mnemonic, Ins.op_str, RSP, getOperandValue(uc, X86.operands[0]), getOperandValue(uc, X86.operands[1]));

							// Translate
							auto TT = getTaintType(X86.operands, X86.op_count);
							this->UT.translateInstruction(Ins, TT);

							// taint the destination
							this->setTaint(uc, X86.operands[0]);

							// (Wrong) remove taint on src
							// Keep the taint otherwise until it get written by something we don't know, otherwise we miss some access
							//this->removeTaint(uc, X86.operands[i]);
						}

						Handled = true;
						break;
					}
				}
				break;
				case CS_OP_IMM: {
					// Not interessting
					// So far we don't have any cases to handle this one
					//printf("Please implement CS_OP_IMM for operand! %i\n", X86.operands[i].type);
				}
				break;
				default:
					printf("Please implement the missing operand! %i\n", X86.operands[i].type);
				}
			}

			// Clean up
			if (count) {
				cs_free(Instructions, count);
			}
		}

		void dumpLLVMTranslation(std::string OutputPath) {
			this->UT.finishLLVMTranslation(OutputPath);
		}

	private:
		uc_engine *uc;
		UniTranslator UT;
		bool TaintAll;

		std::set<int> PushedRegs;
		std::vector<TValue *> TaintedValues;
		std::set<int> EPTaintedValues;
		std::set<uint64_t> EPTaintedValuesSlots;
		std::vector<std::string> TaintedInstructions;

		csh HCapstone;
	};

};