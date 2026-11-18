/**
 * @file src/bin2llvmir/optimizations/inst_opt/inst_opt_pass.cpp
 * @brief LLVM instruction optimization pass.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/CFG.h>

#include <map>
#include <set>
#include <vector>

#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt_pass.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

const std::set<std::string> Eflags = {"cf", "pf", "af", "zf", "sf", "of"};

bool hasOnlyDirectSimpleUses(llvm::GlobalVariable* flag)
{
	for (auto* user : flag->users())
	{
		if (auto* load = dyn_cast<LoadInst>(user))
		{
			if (load->getPointerOperand() == flag && load->isSimple())
			{
				continue;
			}
		}
		if (auto* store = dyn_cast<StoreInst>(user))
		{
			if (store->getPointerOperand() == flag && store->isSimple())
			{
				continue;
			}
		}
		return false;
	}
	return true;
}

bool mayReadFlagsUnknown(llvm::Instruction& insn)
{
	return isa<CallInst>(insn) || isa<InvokeInst>(insn);
}

bool transferFlagBlock(
		llvm::BasicBlock& bb,
		llvm::GlobalVariable* flag,
		bool liveOut)
{
	bool live = liveOut;
	for (auto it = bb.rbegin(); it != bb.rend(); ++it)
	{
		auto& insn = *it;
		if (mayReadFlagsUnknown(insn))
		{
			live = true;
		}
		if (auto* load = dyn_cast<LoadInst>(&insn))
		{
			if (load->getPointerOperand() == flag)
			{
				live = true;
			}
		}
		else if (auto* store = dyn_cast<StoreInst>(&insn))
		{
			if (store->getPointerOperand() == flag)
			{
				live = false;
			}
		}
	}
	return live;
}

bool eliminateDeadFlagStores(llvm::Function& fnc, llvm::GlobalVariable* flag)
{
	std::map<llvm::BasicBlock*, bool> liveIn;
	std::map<llvm::BasicBlock*, bool> liveOut;
	std::vector<llvm::BasicBlock*> blocks;
	for (auto& bb : fnc)
	{
		blocks.push_back(&bb);
		liveIn[&bb] = false;
		liveOut[&bb] = succ_empty(&bb) && !isa<UnreachableInst>(bb.getTerminator());
	}
	bool changed = true;
	while (changed)
	{
		changed = false;
		for (auto it = blocks.rbegin(); it != blocks.rend(); ++it)
		{
			auto& bb = **it;
			bool outgoing = succ_empty(&bb)
					&& !isa<UnreachableInst>(bb.getTerminator());
			for (auto* succ : successors(&bb))
			{
				outgoing |= liveIn[succ];
			}
			bool incoming = transferFlagBlock(bb, flag, outgoing);
			changed |= incoming != liveIn[&bb] || outgoing != liveOut[&bb];
			liveIn[&bb] = incoming;
			liveOut[&bb] = outgoing;
		}
	}

	std::vector<llvm::StoreInst*> dead;
	for (auto& bb : fnc)
	{
		bool live = liveOut[&bb];
		for (auto it = bb.rbegin(); it != bb.rend(); ++it)
		{
			auto& insn = *it;
			if (mayReadFlagsUnknown(insn))
			{
				live = true;
			}
			if (auto* load = dyn_cast<LoadInst>(&insn))
			{
				if (load->getPointerOperand() == flag)
				{
					live = true;
				}
			}
			else if (auto* store = dyn_cast<StoreInst>(&insn))
			{
				if (store->getPointerOperand() == flag)
				{
					if (!live)
					{
						dead.push_back(store);
					}
					live = false;
				}
			}
		}
	}
	for (auto* store : dead)
	{
		store->eraseFromParent();
	}
	return !dead.empty();
}

bool eliminateDeadEflagsStores(llvm::Module& module)
{
	bool changed = false;
	for (auto& global : module.globals())
	{
		if (!Eflags.count(global.getName()) || !hasOnlyDirectSimpleUses(&global))
		{
			continue;
		}
		for (auto& fnc : module)
		{
			if (!fnc.isDeclaration())
			{
				changed |= eliminateDeadFlagStores(fnc, &global);
			}
		}
	}
	return changed;
}

} // namespace

char InstructionOptimizer::ID = 0;

static RegisterPass<InstructionOptimizer> X(
		"retdec-inst-opt",
		"LLVM instruction optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

InstructionOptimizer::InstructionOptimizer() :
		ModulePass(ID)
{

}

bool InstructionOptimizer::runOnModule(Module& m)
{
	_module = &m;
	return run();
}

bool InstructionOptimizer::runOnModuleCustom(llvm::Module& m)
{
	_module = &m;
	return run();
}

bool InstructionOptimizer::run()
{
	bool changed = false;

	// Run before peepholes. Calls and function exits conservatively keep flags
	// live; escaped or volatile flag storage is not analyzed at all.
	changed |= eliminateDeadEflagsStores(*_module);

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction* insn = &*it;
		++it;

		changed |= inst_opt::optimize(insn);
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
