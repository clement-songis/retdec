/**
* @file tests/bin2llvmir/optimizations/inst_opt/inst_opt_pass_tests.cpp
* @brief Tests for the @c InstructionOptimizer pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt_pass.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c InstructionOptimizer pass.
 *
 * This does not test all optimizations, those are tested in
 * @c inst_opt_tests.cpp module. This only tests that pass does something.
 */
class InstructionOptimizerTests: public LlvmIrTests
{
	protected:
		InstructionOptimizer pass;

		unsigned flagStores(const char* functionName = "fnc")
		{
			unsigned count = 0;
			for (auto& bb : *module->getFunction(functionName))
			for (auto& insn : bb)
			{
				auto* store = dyn_cast<StoreInst>(&insn);
				if (store && store->getPointerOperand()->getName() == "zf")
				{
					++count;
				}
			}
			return count;
		}
};

//
// no optimization
//

TEST_F(InstructionOptimizerTests, noOptimizationReturnsFalse)
{
	bool b = pass.runOnModule(*module);

	EXPECT_FALSE(b);
}

TEST_F(InstructionOptimizerTests, optimizationReturnsTrue)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 0
			ret i32 %b
		}
	)");

	bool ret = pass.runOnModuleCustom(*module);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(InstructionOptimizerTests, eflagsLivenessRemovesOverwrittenStore)
{
	parseInput(R"(
		@zf = global i1 0
		define void @fnc() {
			store i1 true, i1* @zf
			store i1 false, i1* @zf
			ret void
		}
	)");
	EXPECT_TRUE(pass.runOnModuleCustom(*module));
	EXPECT_EQ(1, flagStores());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(InstructionOptimizerTests, eflagsLivenessPreservesLoadsAndCalls)
{
	parseInput(R"(
		@zf = global i1 0
		declare void @g()
		define void @fnc() {
			store i1 true, i1* @zf
			%v = load i1, i1* @zf
			call void @g()
			store i1 false, i1* @zf
			ret void
		}
	)");
	pass.runOnModuleCustom(*module);
	EXPECT_EQ(2, flagStores());
}

TEST_F(InstructionOptimizerTests, eflagsLivenessJoinsBranchesConservatively)
{
	parseInput(R"(
		@zf = global i1 0
		define void @fnc(i1 %cond) {
		entry:
			store i1 true, i1* @zf
			br i1 %cond, label %read, label %overwrite
		read:
			%v = load i1, i1* @zf
			ret void
		overwrite:
			store i1 false, i1* @zf
			ret void
		}
	)");
	pass.runOnModuleCustom(*module);
	EXPECT_EQ(2, flagStores());
}

TEST_F(InstructionOptimizerTests, eflagsLivenessSkipsEscapedAndVolatileStorage)
{
	parseInput(R"(
		@zf = global i1 0
		@escape = global i1* @zf
		define void @fnc() {
			store i1 true, i1* @zf
			store i1 false, i1* @zf
			ret void
		}
	)");
	pass.runOnModuleCustom(*module);
	EXPECT_EQ(2, flagStores());
}

TEST_F(InstructionOptimizerTests, eflagsLivenessSkipsVolatileStorage)
{
	parseInput(R"(
		@zf = global i1 0
		define void @fnc() {
			store volatile i1 true, i1* @zf
			store i1 false, i1* @zf
			ret void
		}
	)");
	pass.runOnModuleCustom(*module);
	EXPECT_EQ(2, flagStores());
}

TEST_F(InstructionOptimizerTests, eflagsLivenessRemovesEntryStoreWhenAllBranchesOverwrite)
{
	parseInput(R"(
		@zf = global i1 0
		define void @fnc(i1 %cond) {
		entry:
			store i1 true, i1* @zf
			br i1 %cond, label %left, label %right
		left:
			store i1 false, i1* @zf
			ret void
		right:
			store i1 true, i1* @zf
			ret void
		}
	)");
	EXPECT_TRUE(pass.runOnModuleCustom(*module));
	EXPECT_EQ(2, flagStores());
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
