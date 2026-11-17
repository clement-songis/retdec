/**
* @file tests/bin2llvmir/providers/griffin_sidecar_tests.cpp
* @brief Focused tests for Griffin sidecar parsing and Decoder ret rewriting.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <cstdlib>
#include <memory>

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/providers/griffin_sidecar.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace {

constexpr uint64_t TraceBase = 0x140000000;
constexpr uint64_t RuntimeBase = 0xfffff802b93d0000;
constexpr uint64_t ProvedSiteRva = 0x569140;
constexpr uint64_t ProvedTargetRva = 0x2a9881;

GriffinSidecar loadFixture()
{
	return GriffinSidecar::fromFile(RETDEC_GRIFFIN_TEST_SIDECAR);
}

} // namespace

namespace tests {

class GriffinSidecarTests: public LlvmIrTests
{
};

TEST_F(GriffinSidecarTests, acceptsOnlyProvedStackTrampoline)
{
	auto sidecar = loadFixture();

	EXPECT_EQ(1, sidecar.getRetTargetCount());
	EXPECT_EQ(2, sidecar.getUnresolvedRetCount());
	ASSERT_TRUE(sidecar.getRetTrampolineTarget(RuntimeBase + ProvedSiteRva));
	EXPECT_EQ(RuntimeBase + ProvedTargetRva,
			*sidecar.getRetTrampolineTarget(RuntimeBase + ProvedSiteRva));
	ASSERT_TRUE(sidecar.getRetTrampolineTarget(TraceBase + ProvedSiteRva));
	EXPECT_EQ(TraceBase + ProvedTargetRva,
			*sidecar.getRetTrampolineTarget(TraceBase + ProvedSiteRva));
}

TEST_F(GriffinSidecarTests, unknownAndOrdinaryReturnsStayUnresolved)
{
	auto sidecar = loadFixture();

	EXPECT_FALSE(sidecar.getRetTrampolineTarget(RuntimeBase + 0xac7c));
	// An observed successor without stack-trampoline evidence can be a plain
	// function return and must not be rewritten.
	EXPECT_FALSE(sidecar.getRetTrampolineTarget(RuntimeBase + 0x106270));
	EXPECT_FALSE(sidecar.getRetTrampolineTarget(0x1234));
}

TEST_F(GriffinSidecarTests, realSidecarHasNoProvedRetYet)
{
	const char* path = std::getenv("RETDEC_GRIFFIN_REAL_SIDECAR");
	if (path == nullptr)
	{
		GTEST_SKIP() << "RETDEC_GRIFFIN_REAL_SIDECAR not set";
	}
	auto sidecar = GriffinSidecar::fromFile(path);

	EXPECT_EQ(0, sidecar.getRetTargetCount());
	EXPECT_EQ(25, sidecar.getUnresolvedRetCount());
	EXPECT_FALSE(sidecar.getRetTrampolineTarget(RuntimeBase + ProvedSiteRva));
}

class GriffinDecoderTests: public LlvmIrTests
{
	protected:
		Decoder decoder;
		GriffinSidecar sidecar = loadFixture();

		void prepareDecoder()
		{
			decoder._module = module.get();
			decoder._griffin = std::make_unique<GriffinSidecar>(loadFixture());
		}

		void provedTargetBecomesBranch()
		{
			parseInput(R"(
				declare void @__pseudo_ret(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_ret(i64 0)
					ret i64 0
				target:
					ret i64 0
				}
			)");
			prepareDecoder();
			auto* fnc = getFunctionByName("fnc");
			auto& entry = fnc->getEntryBlock();
			auto* target = &fnc->back();
			auto* pseudo = cast<CallInst>(&entry.front());
			decoder._addr2bb[RuntimeBase + ProvedTargetRva] = target;
			decoder._bb2addr[target] = RuntimeBase + ProvedTargetRva;
			ASSERT_TRUE(decoder.transformToGriffinRetTrampoline(
					RuntimeBase + ProvedSiteRva, pseudo));
			auto* branch = dyn_cast<BranchInst>(entry.getTerminator());
			ASSERT_NE(nullptr, branch);
			EXPECT_EQ(target, branch->getSuccessor(0));
			EXPECT_FALSE(isa<ReturnInst>(entry.getTerminator()));
			EXPECT_FALSE(verifyModule(*module, &errs()));
		}

		void unknownTargetKeepsReturn()
		{
			parseInput(R"(
				declare void @__pseudo_ret(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_ret(i64 0)
					ret i64 0
				}
			)");
			prepareDecoder();
			auto& entry = getFunctionByName("fnc")->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			EXPECT_FALSE(decoder.transformToGriffinRetTrampoline(
					RuntimeBase + 0xac7c, pseudo));
			EXPECT_TRUE(isa<ReturnInst>(entry.getTerminator()));
		}

		void crossFunctionTargetDoesNotBecomeCall()
		{
			parseInput(R"(
				declare void @__pseudo_ret(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_ret(i64 0)
					ret i64 0
				}
				define i64 @other() {
				entry:
					ret i64 0
				}
			)");
			prepareDecoder();
			auto* fnc = getFunctionByName("fnc");
			auto* other = getFunctionByName("other");
			auto& entry = fnc->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			decoder._addr2bb[RuntimeBase + ProvedTargetRva] = &other->getEntryBlock();
			decoder._bb2addr[&other->getEntryBlock()] = RuntimeBase + ProvedTargetRva;
			std::size_t instructionsBefore = entry.size();
			EXPECT_FALSE(decoder.transformToGriffinRetTrampoline(
					RuntimeBase + ProvedSiteRva, pseudo));
			EXPECT_TRUE(isa<ReturnInst>(entry.getTerminator()));
			EXPECT_EQ(instructionsBefore, entry.size());
			EXPECT_EQ(1, std::count_if(entry.begin(), entry.end(),
					[](const Instruction& i) { return isa<CallInst>(i); }));
		}

		void disabledProviderKeepsGenericReturn()
		{
			parseInput(R"(
				declare void @__pseudo_ret(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_ret(i64 0)
					ret i64 0
				}
			)");
			decoder._module = module.get();
			decoder._griffin.reset();
			auto* fnc = getFunctionByName("fnc");
			auto& entry = fnc->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			EXPECT_FALSE(decoder.transformToGriffinRetTrampoline(
					RuntimeBase + ProvedSiteRva, pseudo));
			EXPECT_TRUE(isa<ReturnInst>(entry.getTerminator()));
			EXPECT_EQ(1, fnc->size());
		}

		void undecodedTargetStaysInCurrentFunction()
		{
			parseInput(R"(
				declare void @__pseudo_ret(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_ret(i64 0)
					ret i64 0
				}
			)");
			prepareDecoder();
			auto* fnc = getFunctionByName("fnc");
			auto& entry = fnc->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			ASSERT_TRUE(decoder.transformToGriffinRetTrampoline(
					RuntimeBase + ProvedSiteRva, pseudo));
			auto* branch = cast<BranchInst>(entry.getTerminator());
			EXPECT_EQ(fnc, branch->getSuccessor(0)->getParent());
			EXPECT_EQ(2, fnc->size());
			EXPECT_FALSE(verifyModule(*module, &errs()));
		}
};

TEST_F(GriffinDecoderTests, provedRetTrampolineBecomesBranchNotReturn)
{
	provedTargetBecomesBranch();
}

TEST_F(GriffinDecoderTests, unknownRetKeepsReturnFallback)
{
	unknownTargetKeepsReturn();
}

TEST_F(GriffinDecoderTests, crossFunctionTargetIsNotTurnedIntoCall)
{
	crossFunctionTargetDoesNotBecomeCall();
}

TEST_F(GriffinDecoderTests, disabledProviderKeepsGenericReturnFallback)
{
	disabledProviderKeepsGenericReturn();
}

TEST_F(GriffinDecoderTests, undecodedTargetIsCreatedOnlyInCurrentFunction)
{
	undecodedTargetStaysInCurrentFunction();
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
