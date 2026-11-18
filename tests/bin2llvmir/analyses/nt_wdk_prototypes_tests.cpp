/**
* @file tests/bin2llvmir/analyses/nt_wdk_prototypes_tests.cpp
* @brief Focused tests for generic NT/WDK prototype propagation.
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/analyses/nt_wdk_prototypes.h"
#include "retdec/bin2llvmir/analyses/reachable_funcs_analysis.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

class NtWdkPrototypeTests: public LlvmIrTests
{
};

TEST_F(NtWdkPrototypeTests, refinesKnownDeclarationAndPreservesDirectCallSsa)
{
	parseInput(R"(
		declare i8* @IoAllocateMdl(i8*, i64, i32, i32, i8*)
		define i8* @fnc(i8* %device, i64 %length, i32 %secondary,
				i32 %charge, i8* %irp) {
			%r = call i8* @IoAllocateMdl(i8* %device, i64 %length,
				i32 %secondary, i32 %charge, i8* %irp)
			ret i8* %r
		}
	)");
	EXPECT_EQ(1, NtWdkPrototypes::apply(*module));
	auto* api = module->getFunction("IoAllocateMdl");
	ASSERT_NE(nullptr, api);
	EXPECT_TRUE(api->getReturnType()->isPointerTy());
	EXPECT_EQ("_MDL", api->getReturnType()->getPointerElementType()->getStructName());
	ASSERT_EQ(5, api->arg_size());
	EXPECT_TRUE(api->getFunctionType()->getParamType(1)->isIntegerTy(32));
	EXPECT_TRUE(api->getFunctionType()->getParamType(2)->isIntegerTy(8));
	auto* call = cast<CallInst>(&module->getFunction("fnc")->getEntryBlock().front());
	EXPECT_EQ(api, call->getCalledOperand()->stripPointerCasts());
	EXPECT_TRUE(call->getType()->isPointerTy());
	EXPECT_NE(nullptr, api->getMetadata("wdk.authority"));
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(NtWdkPrototypeTests, preservesAddressTakenUsesThroughOldType)
{
	parseInput(R"(
		declare i8* @MmGetSystemRoutineAddress(i8*)
		@fp = global i8* (i8*)* @MmGetSystemRoutineAddress
	)");
	EXPECT_EQ(1, NtWdkPrototypes::apply(*module));
	auto* api = module->getFunction("MmGetSystemRoutineAddress");
	ASSERT_NE(nullptr, api);
	EXPECT_EQ("_UNICODE_STRING", api->getFunctionType()->getParamType(0)
			->getPointerElementType()->getStructName());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(NtWdkPrototypeTests, leavesMismatchedDefinitionAndVariadicDeclarationUntouched)
{
	parseInput(R"(
		define i32 @KeGetCurrentIrql() {
			ret i32 0
		}
		declare i32 @ZwClose(i8*, ...)
	)");
	EXPECT_EQ(0, NtWdkPrototypes::apply(*module));
	EXPECT_TRUE(module->getFunction("KeGetCurrentIrql")->getReturnType()->isIntegerTy(32));
	EXPECT_TRUE(module->getFunction("ZwClose")->isVarArg());
}

TEST_F(NtWdkPrototypeTests, appliesBeforeIndirectCandidateAnalysis)
{
	parseInput(R"(
		declare i32 @KeGetCurrentIrql()
		define i8 @caller(i8 ()* %fp) {
			%r = call i8 %fp()
			ret i8 %r
		}
	)");
	// Decoder applies prototypes before later CallGraph-based passes. Mirror
	// that ordering here and verify propagation to indirect candidates.
	NtWdkPrototypes::apply(*module);
	CallGraph callGraph(*module);
	auto targets = ReachableFuncsAnalysis::getReachableDefinedFuncsFor(
			*module->getFunction("caller"), *module, callGraph);
	auto* api = module->getFunction("KeGetCurrentIrql");
	ASSERT_NE(nullptr, api);
	EXPECT_TRUE(api->getReturnType()->isIntegerTy(8));
	EXPECT_EQ(1, targets.count(api));
}

TEST_F(NtWdkPrototypeTests, canonicalApplicationIsIdempotent)
{
	parseInput(R"(
		declare i8 @KeGetCurrentIrql()
	)");
	EXPECT_EQ(0, NtWdkPrototypes::apply(*module));
	EXPECT_EQ(0, NtWdkPrototypes::apply(*module));
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
