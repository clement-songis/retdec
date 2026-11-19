/**
* @file tests/bin2llvmir/analyses/tests/reaching_definitions_tests.cpp
* @brief Tests for the uses analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>
#include <utility>
#include <vector>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda_pass.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * Test reaching definition analysis.
 *
 * Richt now, this is just an example, how to create LLVM Module from string,
 * instead of manually constructing it instruction by instruction.
 * => Nowhing useful is tested at the moment.
 */
class ReachingDefinitionsTests: public LlvmIrTests
{
	protected:
		ReachingDefinitionsAnalysis RDA;
};

TEST_F(ReachingDefinitionsTests,
DummyTest)
{
	parseInput(R"(
		@glob0 = global i32 0
		define void @func1() {
			%x = load i32, i32* @glob0
			ret void
		}
	)");

	RDA.runOnModule(*module);

	EXPECT_NE( nullptr, module->getGlobalVariable("glob0") );
	EXPECT_EQ( nullptr, module->getGlobalVariable("glob1") );
}

TEST_F(ReachingDefinitionsTests, MicrosoftX64CallClobbersOnlyCallerSavedRegisters)
{
	parseInput(R"(
		@rax = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@r10 = global i64 0
		@r11 = global i64 0
		@rbx = global i64 0
		@rsi = global i64 0
		@rdi = global i64 0
		@r12 = global i64 0
		declare i64 @g()
		define void @fnc() {
			store i64 1, i64* @rax
			store i64 2, i64* @rcx
			store i64 3, i64* @rdx
			store i64 4, i64* @r8
			store i64 5, i64* @r9
			store i64 6, i64* @r10
			store i64 7, i64* @r11
			store i64 8, i64* @rbx
			store i64 9, i64* @rsi
			store i64 10, i64* @rdi
			store i64 11, i64* @r12
			%call = call i64 @g()
			%after_rax = load i64, i64* @rax
			%after_rcx = load i64, i64* @rcx
			%after_rdx = load i64, i64* @rdx
			%after_r8 = load i64, i64* @r8
			%after_r9 = load i64, i64* @r9
			%after_r10 = load i64, i64* @r10
			%after_r11 = load i64, i64* @r11
			%after_rbx = load i64, i64* @rbx
			%after_rsi = load i64, i64* @rsi
			%after_rdi = load i64, i64* @rdi
			%after_r12 = load i64, i64* @r12
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64"
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto* abi = AbiProvider::addAbi(module.get(), &config);
	const std::vector<std::pair<std::string, uint32_t>> registerIds = {
		{"rax", X86_REG_RAX}, {"rcx", X86_REG_RCX},
		{"rdx", X86_REG_RDX}, {"r8", X86_REG_R8},
		{"r9", X86_REG_R9}, {"r10", X86_REG_R10},
		{"r11", X86_REG_R11}, {"rbx", X86_REG_RBX},
		{"rsi", X86_REG_RSI}, {"rdi", X86_REG_RDI},
		{"r12", X86_REG_R12}
	};
	for (const auto& r : registerIds)
	{
		abi->addRegister(r.second, module->getGlobalVariable(r.first));
	}

	RDA.runOnModule(*module, abi);

	auto* call = getInstructionByName("call");
	for (const auto& r : registerIds)
	{
		auto* load = getInstructionByName("after_" + r.first);
		auto* use = RDA.getUse(load);
		ASSERT_NE(nullptr, use) << r.first;
		ASSERT_EQ(1, use->defs.size()) << r.first;
		auto* def = (*use->defs.begin())->def;
		bool calleeSaved = r.first == "rbx" || r.first == "rsi"
				|| r.first == "rdi" || r.first == "r12";
		if (calleeSaved)
		{
			auto* store = dyn_cast<StoreInst>(def);
			ASSERT_NE(nullptr, store) << r.first;
			EXPECT_EQ(module->getGlobalVariable(r.first),
					store->getPointerOperand()) << r.first;
		}
		else
		{
			EXPECT_EQ(call, def) << r.first;
		}
	}
}

TEST_F(ReachingDefinitionsTests, CallClobberPreventsForwardingButCalleeSavedForwards)
{
	parseInput(R"(
		@rax = global i64 0
		@rbx = global i64 0
		declare i64 @g()
		define i64 @fnc() {
			store i64 11, i64* @rax
			store i64 22, i64* @rbx
			%call = call i64 @g()
			%a = load i64, i64* @rax
			%b = load i64, i64* @rbx
			%r = add i64 %a, %b
			ret i64 %r
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64"
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto* abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_RAX, module->getGlobalVariable("rax"));
	abi->addRegister(X86_REG_RBX, module->getGlobalVariable("rbx"));
	InstructionRdaOptimizer pass;

	bool changed = pass.runOnModuleCustom(*module, abi);

	EXPECT_TRUE(changed);
	std::string exp = R"(
		@rax = global i64 0
		@rbx = global i64 0
		declare i64 @g()
		define i64 @fnc() {
			%call = call i64 @g()
			%a = load i64, i64* @rax
			%r = add i64 %a, 22
			ret i64 %r
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
