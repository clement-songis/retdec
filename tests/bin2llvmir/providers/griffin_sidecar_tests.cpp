/**
* @file tests/bin2llvmir/providers/griffin_sidecar_tests.cpp
* @brief Focused tests for Griffin sidecar parsing and Decoder ret rewriting.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <cstdlib>
#include <memory>

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/providers/griffin_overlay.h"
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

class GriffinSidecarV2Tests: public LlvmIrTests
{
};

class GriffinSidecarStackTests: public LlvmIrTests
{
};

TEST_F(GriffinSidecarStackTests, distinguishesAbiFrameFromVmStorageAndUnknown)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_STACK_TEST_SIDECAR);

	EXPECT_EQ(5, sidecar.getStackSlotCount());
	EXPECT_EQ(1, sidecar.getAbiFrameStackSlotCount());
	auto abi = sidecar.getStackSlot(TraceBase + 0x1000);
	ASSERT_TRUE(abi);
	EXPECT_EQ(0x20, abi->displacement);
	EXPECT_EQ(8, abi->size);
	EXPECT_EQ(0x7000000020, abi->address);
	EXPECT_EQ(GriffinSidecar::StackSlotRole::AbiFrame, abi->role);
	auto vmRegister = sidecar.getStackSlot(TraceBase + 0x1010);
	ASSERT_TRUE(vmRegister);
	EXPECT_EQ(0x28, vmRegister->displacement);
	EXPECT_EQ(GriffinSidecar::StackSlotRole::VmRegister, vmRegister->role);
	auto vmSpill = sidecar.getStackSlot(TraceBase + 0x1020);
	ASSERT_TRUE(vmSpill);
	EXPECT_EQ(GriffinSidecar::StackSlotRole::VmSpill, vmSpill->role);
	auto unknown = sidecar.getStackSlot(TraceBase + 0x1030);
	ASSERT_TRUE(unknown);
	EXPECT_EQ(GriffinSidecar::StackSlotRole::Unknown, unknown->role);
}

TEST_F(GriffinSidecarStackTests, rejectsUnprovedMemoryAndConflictingRoles)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_STACK_TEST_SIDECAR);

	EXPECT_FALSE(sidecar.getStackSlot(TraceBase + 0x1040));
	EXPECT_FALSE(sidecar.getStackSlot(TraceBase + 0x1048));
	auto conflict = sidecar.getStackSlot(TraceBase + 0x1050);
	ASSERT_TRUE(conflict);
	EXPECT_EQ(GriffinSidecar::StackSlotRole::Unknown, conflict->role);
}

TEST_F(GriffinSidecarStackTests, realObservationsRemainUnknownWithoutRoleProof)
{
	const char* path = std::getenv("RETDEC_GRIFFIN_REAL_STACK_SIDECAR");
	if (path == nullptr)
	{
		GTEST_SKIP() << "RETDEC_GRIFFIN_REAL_STACK_SIDECAR not set";
	}
	auto sidecar = GriffinSidecar::fromFile(path);

	EXPECT_GT(sidecar.getStackSlotCount(), 0);
	EXPECT_EQ(0, sidecar.getAbiFrameStackSlotCount());
	auto slot = sidecar.getStackSlot(TraceBase + 0xc1c13b);
	ASSERT_TRUE(slot);
	EXPECT_EQ(0x70, slot->displacement);
	EXPECT_EQ(GriffinSidecar::StackSlotRole::Unknown, slot->role);
}

TEST_F(GriffinSidecarV2Tests, witnessPromotesStaticAndDynamicVerifiedOnly)
{
	const char* path = std::getenv("RETDEC_GRIFFIN_V2_WITNESS");
	if (path == nullptr)
	{
		GTEST_SKIP() << "RETDEC_GRIFFIN_V2_WITNESS not set";
	}
	auto sidecar = GriffinSidecar::fromFile(path);

	ASSERT_TRUE(sidecar.isEvidenceV2());
	EXPECT_TRUE(sidecar.checkImageSha256(
			"c8ca7db29692b5e5317c66f980ea45b868cb28466edd5e57d9439cceee88e390"));
	EXPECT_FALSE(sidecar.checkImageSha256(std::string(64, '0')));
	EXPECT_EQ(5, sidecar.getControlTargetCount());
	EXPECT_EQ(1, sidecar.getDynamicVerifiedTargetCount());
	ASSERT_TRUE(sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(TraceBase + 0x2a9881,
			*sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	ASSERT_TRUE(sidecar.getControlTarget(TraceBase + 0x58df90, "jmp"));
	EXPECT_EQ(TraceBase + 0x27cee7,
			*sidecar.getControlTarget(TraceBase + 0x58df90, "jmp"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0x569140, "ret"));
	EXPECT_FALSE(sidecar.getRetTrampolineTarget(TraceBase + 0x569140));
	EXPECT_EQ(1, sidecar.getUnresolvedRetCount());
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x58df90, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x569140, "ret"));
	ASSERT_TRUE(sidecar.getControlTarget(RuntimeBase + 0x463ade, "call"));
	EXPECT_EQ(RuntimeBase + 0x2a9881,
			*sidecar.getControlTarget(RuntimeBase + 0x463ade, "call"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(RuntimeBase + 0x58df90, "jmp"));
}

TEST_F(GriffinSidecarV2Tests, migrationDoesNotPromoteHistoricalDynamicEdges)
{
	const char* path = std::getenv("RETDEC_GRIFFIN_V2_MIGRATED");
	if (path == nullptr)
	{
		GTEST_SKIP() << "RETDEC_GRIFFIN_V2_MIGRATED not set";
	}
	auto sidecar = GriffinSidecar::fromFile(path);

	EXPECT_EQ(30, sidecar.getControlTargetCount());
	EXPECT_EQ(0, sidecar.getDynamicVerifiedTargetCount());
	// One of the 38 historical dynamic edges without a complete context.
	EXPECT_FALSE(sidecar.getControlTarget(RuntimeBase + 0xf7daed, "call"));
	ASSERT_TRUE(sidecar.getControlTarget(RuntimeBase + 0x463ade, "call"));
	EXPECT_EQ(RuntimeBase + 0x2a9881,
			*sidecar.getControlTarget(RuntimeBase + 0x463ade, "call"));
	EXPECT_FALSE(sidecar.getRetTrampolineTarget(RuntimeBase + 0x569140));
	EXPECT_EQ(25, sidecar.getUnresolvedRetCount());
}

TEST_F(GriffinSidecarV2Tests, rejectsScratchAmbiguousMultiTargetAndBadReplay)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_V2_TEST_SIDECAR);

	EXPECT_TRUE(sidecar.checkImageSha256(
			"c8ca7db29692b5e5317c66f980ea45b868cb28466edd5e57d9439cceee88e390"));
	EXPECT_FALSE(sidecar.checkImageSha256(std::string(64, '0')));
	EXPECT_EQ(1, sidecar.getControlTargetCount());
	EXPECT_EQ(0, sidecar.getDynamicVerifiedTargetCount());
	ASSERT_TRUE(sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(TraceBase + 0x2a9881,
			*sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0x569140, "ret"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0xbeef, "jmp"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0xcafe, "jmp"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0xdead, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0xbeef, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0xcafe, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0xdead, "jmp"));
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

		void prepareV2Decoder()
		{
			auto config = Config::empty(module.get());
			config.getConfig().architecture.setName("x86-64");
			decoder._module = module.get();
			decoder._config = &config;
			decoder._abi = AbiProvider::addAbi(module.get(), &config);
			decoder._griffin = std::make_unique<GriffinSidecar>(
					GriffinSidecar::fromFile(std::getenv("RETDEC_GRIFFIN_V2_WITNESS")));
		}

		void provedCallBecomesCall()
		{
			parseInput(R"(
				declare void @__pseudo_call(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_call(i64 0)
					ret i64 0
				}
				define i64 @target() {
				entry:
					ret i64 0
				}
			)");
			prepareV2Decoder();
			auto* targetFnc = getFunctionByName("target");
			decoder._addr2fnc[TraceBase + ProvedTargetRva] = targetFnc;
			decoder._fnc2addr[targetFnc] = TraceBase + ProvedTargetRva;
			auto& entry = getFunctionByName("fnc")->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			ASSERT_TRUE(decoder.transformToGriffinCall(
					TraceBase + 0x463ade, pseudo));
			auto it = entry.begin();
			++it;
			auto* realCall = cast<CallInst>(&*it);
			EXPECT_EQ(targetFnc, realCall->getCalledFunction());
		}

		void provedJumpMergesPlaceholderWithoutCall()
		{
			parseInput(R"(
				declare void @__pseudo_br(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_br(i64 0)
					ret i64 0
				}
				define i64 @target() {
				entry:
					ret i64 0
				}
			)");
			prepareV2Decoder();
			auto* fnc = getFunctionByName("fnc");
			auto* targetFnc = getFunctionByName("target");
			auto* targetBb = &targetFnc->getEntryBlock();
			decoder._addr2fnc[TraceBase + 0x27cee7] = targetFnc;
			decoder._fnc2addr[targetFnc] = TraceBase + 0x27cee7;
			decoder._addr2bb[TraceBase + 0x27cee7] = targetBb;
			decoder._bb2addr[targetBb] = TraceBase + 0x27cee7;
			auto& entry = fnc->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			ASSERT_TRUE(decoder.transformToGriffinJump(
					TraceBase + 0x58df90, pseudo, TraceBase + 0x58df92));
			auto* branch = cast<BranchInst>(entry.getTerminator());
			EXPECT_EQ(fnc, branch->getSuccessor(0)->getParent());
			EXPECT_EQ(2, module->getFunctionList().size());
			EXPECT_EQ(1, std::count_if(entry.begin(), entry.end(),
					[](const Instruction& i) { return isa<CallInst>(i); }));
		}

		void overlappingJumpTargetIsAllowed()
		{
			parseInput(R"(
				declare void @__pseudo_br(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_br(i64 0)
					ret i64 0
				}
				define i64 @target() {
				entry:
					ret i64 0
				extra:
					ret i64 0
				}
				define void @caller() {
				entry:
					%0 = call i64 @target()
					ret void
				}
			)");
			prepareV2Decoder();
			auto* fnc = getFunctionByName("fnc");
			auto* targetFnc = getFunctionByName("target");
			auto* targetBb = &targetFnc->getEntryBlock();
			decoder._addr2fnc[TraceBase + 0x58df80] = targetFnc;
			decoder._fnc2addr[targetFnc] = TraceBase + 0x58df80;
			decoder._addr2bb[TraceBase + 0x58df80] = targetBb;
			decoder._bb2addr[targetBb] = TraceBase + 0x58df80;
			auto& entry = fnc->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			ASSERT_TRUE(decoder.transformToGriffinJump(
					TraceBase + 0x58df7f, pseudo, TraceBase + 0x58df81));
			auto* branch = cast<BranchInst>(entry.getTerminator());
			EXPECT_EQ(fnc, branch->getSuccessor(0)->getParent());
			EXPECT_EQ(2, fnc->size());
			EXPECT_NE(nullptr, getFunctionByName("target"));
			EXPECT_FALSE(verifyModule(*module, &errs()));
			EXPECT_EQ(1, std::count_if(entry.begin(), entry.end(),
					[](const Instruction& i) { return isa<CallInst>(i); }));
		}

		void overlappedTargetRangeSurvivesAndRejectedRetDoesNot()
		{
			decoder._griffin = std::make_unique<GriffinSidecar>(
					GriffinSidecar::fromFile(std::getenv("RETDEC_GRIFFIN_V2_WITNESS")));
			decoder._griffinOverlay = std::make_unique<GriffinOverlay>(
					GriffinOverlay::fromFile(std::getenv("RETDEC_GRIFFIN_OVERLAY")));
			auto start = RuntimeBase + 0x58df7f;
			auto end = RuntimeBase + 0x58df81;
			decoder._ranges.addPrimary(start, end);

			decoder.removeDecodedRange(start, end, false);

			auto* preserved = decoder._ranges.getPrimary(RuntimeBase + 0x58df80);
			ASSERT_NE(nullptr, preserved);
			EXPECT_EQ(RuntimeBase + 0x58df80, preserved->getStart());
			EXPECT_EQ(end, preserved->getEnd());

			auto rejected = RuntimeBase + 0x569140;
			decoder._ranges.addPrimary(rejected, rejected + 1);
			decoder.removeDecodedRange(rejected, rejected + 1, false);
			EXPECT_EQ(nullptr, decoder._ranges.getPrimary(rejected));
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

TEST_F(GriffinDecoderTests, provedCallBecomesCall)
{
	provedCallBecomesCall();
}

TEST_F(GriffinDecoderTests, provedJumpMergesPlaceholderWithoutCall)
{
	provedJumpMergesPlaceholderWithoutCall();
}

TEST_F(GriffinDecoderTests, overlappingJumpTargetIsAllowed)
{
	overlappingJumpTargetIsAllowed();
}

TEST_F(GriffinDecoderTests, overlappedTargetRangeSurvivesAndRejectedRetDoesNot)
{
	overlappedTargetRangeSurvivesAndRejectedRetDoesNot();
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
