/**
* @file src/bin2llvmir/analyses/nt_wdk_prototypes.cpp
* @brief Official NT/WDK prototypes for known external declarations.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Metadata.h>

#include <map>
#include <string>
#include <vector>

#include "retdec/bin2llvmir/analyses/nt_wdk_prototypes.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace {

struct Prototype
{
	const char* result;
	std::vector<const char*> arguments;
	const char* authority;
};

const std::map<std::string, Prototype> Prototypes = {
	{"KeAcquireGuardedMutex", {"void", {"%_KGUARDED_MUTEX*"}, "wdm.h/nf-wdm-keacquireguardedmutex"}},
	{"KeReleaseGuardedMutex", {"void", {"%_KGUARDED_MUTEX*"}, "wdm.h/nf-wdm-kereleaseguardedmutex"}},
	{"ExAcquirePushLockExclusiveEx", {"void", {"%_EX_PUSH_LOCK*", "i32"}, "wdm.h/nf-wdm-exacquirepushlockexclusiveex"}},
	{"ExReleasePushLockExclusiveEx", {"void", {"%_EX_PUSH_LOCK*", "i32"}, "wdm.h/nf-wdm-exreleasepushlockexclusiveex"}},
	{"IoGetCurrentProcess", {"%_EPROCESS*", {}, "wdm.h/nf-wdm-iogetcurrentprocess"}},
	{"IoAllocateMdl", {"%_MDL*", {"%_DEVICE_OBJECT*", "i32", "i8", "i8", "%_IRP*"}, "wdm.h/nf-wdm-ioallocatemdl"}},
	{"IoFreeMdl", {"void", {"%_MDL*"}, "wdm.h/nf-wdm-iofreemdl"}},
	{"MmGetSystemRoutineAddress", {"i8*", {"%_UNICODE_STRING*"}, "wdm.h/nf-wdm-mmgetsystemroutineaddress"}},
	{"ObReferenceObjectByPointer", {"i32", {"i8*", "i32", "%_OBJECT_TYPE*", "i8"}, "wdm.h/nf-wdm-obreferenceobjectbypointer"}},
	{"RtlPcToFileHeader", {"i8*", {"i8*", "i8**"}, "wdm.h/nf-wdm-rtlpctofileheader"}},
	{"ZwClose", {"i32", {"i8*"}, "wdm.h/nf-wdm-zwclose"}},
	{"KeGetCurrentIrql", {"i8", {}, "wdm.h/nf-wdm-kegetcurrentirql"}},
	{"KfRaiseIrql", {"i8", {"i8"}, "wdm.h/nf-wdm-kfraiseirql"}},
	{"KeLowerIrql", {"void", {"i8"}, "wdm.h/nf-wdm-kelowerirql"}},
	{"KeWaitForSingleObject", {"i32", {"i8*", "i32", "i8", "i8", "i8*"}, "wdm.h/nf-wdm-kewaitforsingleobject"}}
};

Type* typeFromName(Module& module, const std::string& name)
{
	auto& context = module.getContext();
	if (name == "void") return Type::getVoidTy(context);
	if (name == "i8") return Type::getInt8Ty(context);
	if (name == "i32") return Type::getInt32Ty(context);
	if (name == "i8*") return Type::getInt8PtrTy(context);
	if (name == "i8**") return PointerType::get(Type::getInt8PtrTy(context), 0);
	if (name.front() == '%' && name.back() == '*')
	{
		auto structName = name.substr(1, name.size() - 2);
		auto* type = module.getTypeByName(structName);
		if (type == nullptr)
		{
			type = StructType::create(context, structName);
		}
		return PointerType::get(type, 0);
	}
	return nullptr;
}

FunctionType* prototypeType(Module& module, const Prototype& prototype)
{
	std::vector<Type*> arguments;
	for (const char* name : prototype.arguments)
	{
		auto* type = typeFromName(module, name);
		if (type == nullptr)
		{
			return nullptr;
		}
		arguments.push_back(type);
	}
	auto* result = typeFromName(module, prototype.result);
	return result ? FunctionType::get(result, arguments, false) : nullptr;
}

void attachProvenance(Function& function, const Prototype& prototype)
{
	auto& context = function.getContext();
	function.setMetadata("wdk.authority", MDNode::get(context,
			MDString::get(context,
					std::string("Microsoft WDK ") + prototype.authority)));
}

} // namespace

std::size_t NtWdkPrototypes::apply(llvm::Module& module)
{
	std::size_t changed = 0;
	for (const auto& item : Prototypes)
	{
		auto* old = module.getFunction(item.first);
		if (old == nullptr)
		{
			continue;
		}
		auto* type = prototypeType(module, item.second);
		if (type == nullptr)
		{
			continue;
		}
		if (old->getFunctionType() == type)
		{
			attachProvenance(*old, item.second);
			continue;
		}
		// Rebuilding a body with different SSA argument types is unsafe. Known
		// declarations can be replaced while all old uses keep their ABI type
		// through a constant bitcast to the old function-pointer type.
		if (!old->isDeclaration() || old->isVarArg())
		{
			continue;
		}

		auto* replacement = Function::Create(
				type, old->getLinkage(), old->getName() + ".ntwdk", &module);
		// Parameter/return attributes are type-specific (sret, byval, ...).
		// Keep ABI linkage properties, not potentially incompatible old attrs.
		replacement->setVisibility(old->getVisibility());
		replacement->setDLLStorageClass(old->getDLLStorageClass());
		replacement->setUnnamedAddr(old->getUnnamedAddr());
		replacement->setCallingConv(old->getCallingConv());
		if (!old->use_empty())
		{
			auto* compatible = ConstantExpr::getBitCast(replacement, old->getType());
			old->replaceAllUsesWith(compatible);
		}
		old->eraseFromParent();
		replacement->setName(item.first);
		attachProvenance(*replacement, item.second);
		++changed;
	}
	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
