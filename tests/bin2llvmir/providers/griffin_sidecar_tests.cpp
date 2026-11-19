/**
* @file tests/bin2llvmir/providers/griffin_sidecar_tests.cpp
* @brief Focused tests for Griffin sidecar parsing and Decoder ret rewriting.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <cstdlib>
#include <memory>
#include <string>

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/raw_ostream.h>

#include "bin2llvmir/utils/llvmir_tests.h"
#include "llvmir2hll/config/config_mock.h"
#include "llvmir2hll/semantics/semantics_mock.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/optimizations/stack/stack.h"
#include "retdec/bin2llvmir/providers/griffin_overlay.h"
#include "retdec/bin2llvmir/providers/griffin_sidecar.h"
#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/hll/hll_writers/c_hll_writer.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace {

constexpr uint64_t TraceBase = 0x140000000;
constexpr uint64_t RuntimeBase = 0xfffff802b93d0000;
constexpr uint64_t ProvedSiteRva = 0x569140;
constexpr uint64_t ProvedTargetRva = 0x2a9881;

char CffConversionPassId = 0;

class CffConversionPass: public llvm::ModulePass
{
	public:
		CffConversionPass():
				llvm::ModulePass(CffConversionPassId),
				config(std::make_shared<::testing::NiceMock<
						retdec::llvmir2hll::tests::ConfigMock>>()),
				semantics(std::make_shared<::testing::NiceMock<
						retdec::llvmir2hll::tests::SemanticsMock>>())
		{
			ON_CALL(*config, getAddressRangeForFunc(_))
					.WillByDefault(Return(retdec::llvmir2hll::NO_ADDRESS_RANGE));
		}

		bool runOnModule(llvm::Module& llvmModule) override
		{
			auto converter = retdec::llvmir2hll::LLVMIR2BIRConverter::create(this);
			birModule = converter->convert(
					&llvmModule,
					llvmModule.getModuleIdentifier(),
					semantics,
					config);
			return false;
		}

		void getAnalysisUsage(llvm::AnalysisUsage& au) const override
		{
			au.addRequired<llvm::LoopInfoWrapperPass>();
			au.addRequired<llvm::ScalarEvolutionWrapperPass>();
			au.setPreservesAll();
		}

		std::string emitC() const
		{
			if (birModule == nullptr)
			{
				return "";
			}
			std::string code;
			llvm::raw_string_ostream stream(code);
			auto writer = retdec::llvmir2hll::CHLLWriter::create(stream);
			writer->emitTargetCode(birModule);
			stream.flush();
			return code;
		}

	private:
		std::shared_ptr<retdec::llvmir2hll::tests::ConfigMock> config;
		std::shared_ptr<retdec::llvmir2hll::tests::SemanticsMock> semantics;
		retdec::llvmir2hll::ShPtr<retdec::llvmir2hll::Module> birModule;
};

std::string convertToC(llvm::Module& module)
{
	llvm::legacy::PassManager passManager;
	passManager.add(new llvm::LoopInfoWrapperPass());
	passManager.add(new llvm::ScalarEvolutionWrapperPass());
	auto* conversionPass = new CffConversionPass();
	passManager.add(conversionPass);
	passManager.run(module);
	return conversionPass->emitC();
}

std::string printModule(llvm::Module& module)
{
	std::string ir;
	llvm::raw_string_ostream stream(ir);
	module.print(stream, nullptr);
	stream.flush();
	return ir;
}

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

TEST_F(GriffinSidecarStackTests, rejectsIncompleteTaintedAndMismatchedContexts)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_STACK_TEST_SIDECAR);

	for (uint64_t rva : {0x1060, 0x1068, 0x1070, 0x1078, 0x1080})
	{
		EXPECT_FALSE(sidecar.getStackSlot(TraceBase + rva)) << std::hex << rva;
	}
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

class GriffinSidecarCffTests: public LlvmIrTests
{
};

TEST_F(GriffinSidecarCffTests, acceptsOnlyCompleteReplayedTargetSets)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_CFF_TEST_SIDECAR);

	EXPECT_EQ(3, sidecar.getControlTargetSetCount());
	EXPECT_EQ(1, sidecar.getControlTargetCount());
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x5000, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x6000, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x7000, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x7010, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x9000, "jmp"));
	EXPECT_FALSE(sidecar.getControlTargetSet(TraceBase + 0x7000, "jmp"));
	EXPECT_FALSE(sidecar.getControlTargetSet(TraceBase + 0x7010, "jmp"));
	EXPECT_FALSE(sidecar.getControlTargetSet(TraceBase + 0x9000, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0xa010, "jmp"));
	EXPECT_EQ(TraceBase + 0x3000,
			*sidecar.getControlTarget(TraceBase + 0xa010, "jmp"));
}

TEST_F(GriffinSidecarCffTests, rejectsBadCaseShapesAndIncompleteSingletons)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_CFF_TEST_SIDECAR);

	for (uint64_t rva : {0x7020, 0x7030, 0x7040, 0x9000, 0x9010, 0x9020,
			0x9030, 0x9040, 0x9050, 0x9060, 0xa000, 0xa020})
	{
		EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
				sidecar.getControlStatus(TraceBase + rva, "jmp")) << std::hex << rva;
		EXPECT_FALSE(sidecar.getControlTargetSet(TraceBase + rva, "jmp"));
		EXPECT_FALSE(sidecar.getControlTarget(TraceBase + rva, "jmp"));
	}
}

TEST_F(GriffinSidecarCffTests, exposesStateCasesOnlyWithMatchingObservations)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_CFF_TEST_SIDECAR);
	auto switchSet = sidecar.getControlTargetSet(TraceBase + 0x5000, "jmp");
	ASSERT_TRUE(switchSet);
	ASSERT_EQ(2, switchSet->targets.size());
	EXPECT_TRUE(switchSet->stateFromPseudoArgument);
	EXPECT_EQ(TraceBase + 0x3000, switchSet->targets[0].target);
	ASSERT_TRUE(switchSet->targets[0].stateValue);
	EXPECT_EQ(7, *switchSet->targets[0].stateValue);
	EXPECT_EQ(TraceBase + 0x4000, switchSet->targets[1].target);
	ASSERT_TRUE(switchSet->targets[1].stateValue);
	EXPECT_EQ(11, *switchSet->targets[1].stateValue);

	auto indirectSet = sidecar.getControlTargetSet(RuntimeBase + 0x6000, "jmp");
	ASSERT_TRUE(indirectSet);
	EXPECT_FALSE(indirectSet->stateFromPseudoArgument);
	EXPECT_EQ(RuntimeBase + 0x3000, indirectSet->targets[0].target);
	EXPECT_FALSE(indirectSet->targets[0].stateValue);
}

TEST_F(GriffinSidecarCffTests, realObservedSetsStayRejectedWithoutCompletenessProof)
{
	const char* path = std::getenv("RETDEC_GRIFFIN_REAL_STACK_SIDECAR");
	if (path == nullptr)
	{
		GTEST_SKIP() << "RETDEC_GRIFFIN_REAL_STACK_SIDECAR not set";
	}
	auto sidecar = GriffinSidecar::fromFile(path);

	EXPECT_EQ(0, sidecar.getControlTargetSetCount());
	EXPECT_FALSE(sidecar.getControlTargetSet(TraceBase + 0x2a5377, "ret"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x2a5377, "ret"));
}

TEST_F(GriffinSidecarV2Tests, witnessSeparatesTransferProofFromSetCompleteness)
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
	EXPECT_EQ(4, sidecar.getControlTargetCount());
	EXPECT_EQ(0, sidecar.getDynamicVerifiedTargetCount());
	ASSERT_TRUE(sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(TraceBase + 0x2a9881,
			*sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	// The dynamic transfer is replayed, but its target set is not complete.
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0x58df90, "jmp"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0x569140, "ret"));
	EXPECT_FALSE(sidecar.getRetTrampolineTarget(TraceBase + 0x569140));
	EXPECT_EQ(1, sidecar.getUnresolvedRetCount());
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x58df90, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x569140, "ret"));
	ASSERT_TRUE(sidecar.getControlTarget(RuntimeBase + 0x463ade, "call"));
	EXPECT_EQ(RuntimeBase + 0x2a9881,
			*sidecar.getControlTarget(RuntimeBase + 0x463ade, "call"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
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

TEST_F(GriffinSidecarV2Tests, rejectsIncompleteSingletonScratchAmbiguousMultiTargetAndBadReplay)
{
	auto sidecar = GriffinSidecar::fromFile(RETDEC_GRIFFIN_V2_TEST_SIDECAR);

	EXPECT_TRUE(sidecar.checkImageSha256(
			"c8ca7db29692b5e5317c66f980ea45b868cb28466edd5e57d9439cceee88e390"));
	EXPECT_FALSE(sidecar.checkImageSha256(std::string(64, '0')));
	EXPECT_EQ(2, sidecar.getControlTargetCount());
	EXPECT_EQ(0, sidecar.getDynamicVerifiedTargetCount());
	ASSERT_TRUE(sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(TraceBase + 0x2a9881,
			*sidecar.getControlTarget(TraceBase + 0x463ade, "call"));
	ASSERT_TRUE(sidecar.getControlTarget(TraceBase + 0x58df7f, "jmp"));
	EXPECT_EQ(TraceBase + 0x58df80,
			*sidecar.getControlTarget(TraceBase + 0x58df7f, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x463ade, "call"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Proven,
			sidecar.getControlStatus(TraceBase + 0x58df7f, "jmp"));
	// Dynamic singleton replay alone is insufficient without set completeness.
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0x58df90, "jmp"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x58df90, "jmp"));
	EXPECT_FALSE(sidecar.getControlTarget(TraceBase + 0x569140, "ret"));
	EXPECT_EQ(GriffinSidecar::ControlStatus::Rejected,
			sidecar.getControlStatus(TraceBase + 0x569140, "ret"));
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
		std::unique_ptr<Config> v2Config;
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
			v2Config = std::make_unique<Config>(Config::empty(module.get()));
			v2Config->getConfig().architecture.setName("x86-64");
			decoder._module = module.get();
			decoder._config = v2Config.get();
			decoder._abi = AbiProvider::addAbi(module.get(), v2Config.get());
			decoder._griffin = std::make_unique<GriffinSidecar>(
					GriffinSidecar::fromFile(RETDEC_GRIFFIN_V2_TEST_SIDECAR));
		}

		void rejectedAndScratchControlsLeaveModuleUnchanged()
		{
			parseInput(R"(
				declare void @__pseudo_br(i64)
				declare void @__pseudo_ret(i64)
				define i64 @fnc() {
				entry:
					call void @__pseudo_br(i64 1)
					call void @__pseudo_br(i64 2)
					call void @__pseudo_br(i64 3)
					call void @__pseudo_br(i64 4)
					call void @__pseudo_ret(i64 0)
					ret i64 0
				}
			)");
			prepareV2Decoder();
			auto before = llvmObjToString(module.get());
			auto& entry = getFunctionByName("fnc")->getEntryBlock();
			auto it = entry.begin();
			for (uint64_t site : {0x58df90, 0xbeef, 0xcafe, 0xdead})
			{
				auto* pseudo = cast<CallInst>(&*it++);
				EXPECT_FALSE(decoder.transformToGriffinJump(
						TraceBase + site, pseudo, TraceBase + site + 1));
			}
			auto* scratchRet = cast<CallInst>(&*it);
			EXPECT_FALSE(decoder.transformToGriffinRetTrampoline(
					TraceBase + 0x569140, scratchRet));

			EXPECT_EQ(before, llvmObjToString(module.get()));
			EXPECT_FALSE(verifyModule(*module, &errs()));
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
			decoder._griffin = std::make_unique<GriffinSidecar>(
					GriffinSidecar::fromFile(RETDEC_GRIFFIN_CFF_TEST_SIDECAR));
			auto* fnc = getFunctionByName("fnc");
			auto* targetFnc = getFunctionByName("target");
			auto* targetBb = &targetFnc->getEntryBlock();
			decoder._addr2fnc[TraceBase + 0x3000] = targetFnc;
			decoder._fnc2addr[targetFnc] = TraceBase + 0x3000;
			decoder._addr2bb[TraceBase + 0x3000] = targetBb;
			decoder._bb2addr[targetBb] = TraceBase + 0x3000;
			auto& entry = fnc->getEntryBlock();
			auto* pseudo = cast<CallInst>(&entry.front());
			ASSERT_TRUE(decoder.transformToGriffinJump(
					TraceBase + 0xa010, pseudo, TraceBase + 0xa012));
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
			auto* cloned = branch->getSuccessor(0);
			EXPECT_EQ(fnc, cloned->getParent());
			EXPECT_EQ(2, fnc->size());
			EXPECT_NE(nullptr, getFunctionByName("target"));
			EXPECT_EQ(cloned, decoder._addr2bb.at(TraceBase + 0x58df80));
			EXPECT_EQ(TraceBase + 0x58df80, decoder._bb2addr.at(cloned));
			EXPECT_EQ(0, decoder._bb2addr.count(targetBb));
			EXPECT_EQ(1, std::count_if(
					decoder._addr2bb.begin(), decoder._addr2bb.end(),
					[](const auto& item) {
						return item.first == TraceBase + 0x58df80;
					}));
			EXPECT_FALSE(verifyModule(*module, &errs()));
			EXPECT_EQ(1, std::count_if(entry.begin(), entry.end(),
					[](const Instruction& i) { return isa<CallInst>(i); }));
		}

		void unsafeJumpTargetDoesNotBecomeCall()
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
					unreachable
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
			auto instructionsBefore = entry.size();

			EXPECT_FALSE(decoder.transformToGriffinJump(
					TraceBase + 0x58df90, pseudo, TraceBase + 0x58df92));
			EXPECT_TRUE(isa<ReturnInst>(entry.getTerminator()));
			EXPECT_EQ(instructionsBefore, entry.size());
			EXPECT_EQ(1, std::count_if(entry.begin(), entry.end(),
					[](const Instruction& i) { return isa<CallInst>(i); }));
			EXPECT_EQ(targetFnc, targetBb->getParent());
			EXPECT_FALSE(verifyModule(*module, &errs()));
		}

		void overlappedTargetRangeSurvivesAndRejectedRetDoesNot()
		{
			decoder._griffin = std::make_unique<GriffinSidecar>(
					GriffinSidecar::fromFile(RETDEC_GRIFFIN_V2_TEST_SIDECAR));
			decoder._griffinOverlay = std::make_unique<GriffinOverlay>(
					GriffinOverlay::fromFile(RETDEC_GRIFFIN_OVERLAY_WITNESS_TEST));
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

class GriffinCffDecoderTests: public LlvmIrTests
{
	protected:
		Decoder decoder;

		bool transform(common::Address site, llvm::CallInst* pseudo)
		{
			return decoder.transformToGriffinJump(site, pseudo, site + 5);
		}

		bool transformSet(
				common::Address site,
				llvm::CallInst* pseudo,
				const GriffinSidecar::ControlFlowTargetSet& targetSet)
		{
			return decoder.transformToGriffinControlFlowSet(
					site, pseudo, site + 5, targetSet);
		}

		void prepareDecoder()
		{
			decoder._module = module.get();
			decoder._griffin = std::make_unique<GriffinSidecar>(
					GriffinSidecar::fromFile(RETDEC_GRIFFIN_CFF_TEST_SIDECAR));
		}

		void registerTargets(
				llvm::BasicBlock*& entry,
				llvm::BasicBlock*& case7,
				llvm::BasicBlock*& case11)
		{
			auto* fnc = getFunctionByName("fnc");
			auto it = fnc->begin();
			entry = &*it++;
			case7 = &*it++;
			case11 = &*it;
			decoder._addr2bb[TraceBase + 0x3000] = case7;
			decoder._bb2addr[case7] = TraceBase + 0x3000;
			decoder._addr2bb[TraceBase + 0x4000] = case11;
			decoder._bb2addr[case11] = TraceBase + 0x4000;
		}

		void unregisterSecondTarget(llvm::BasicBlock* target)
		{
			decoder._addr2bb.erase(TraceBase + 0x4000);
			decoder._bb2addr.erase(target);
		}

		void lateUnsafeTargetDoesNotPartiallyMergeSet();
		void missingStateDoesNotPartiallyRewriteSet();

		void checkOverlappedTargets()
		{
			prepareDecoder();
			decoder._griffinOverlay = std::make_unique<GriffinOverlay>(
					GriffinOverlay::fromFile(RETDEC_GRIFFIN_OVERLAY_TEST));
			auto start = TraceBase + 0x8000;
			auto end = TraceBase + 0x8003;
			decoder._ranges.addPrimary(start, end);

			decoder.removeDecodedRange(start, end, false);

			auto* first = decoder._ranges.getPrimary(TraceBase + 0x8001);
			auto* second = decoder._ranges.getPrimary(TraceBase + 0x8002);
			ASSERT_NE(nullptr, first);
			ASSERT_NE(nullptr, second);
			EXPECT_EQ(TraceBase + 0x8001, first->getStart());
			EXPECT_EQ(end, first->getEnd());
			EXPECT_TRUE(first->contains(TraceBase + 0x8002));
		}
};

class GriffinStackAnalysisTests: public LlvmIrTests
{
	protected:
		std::unique_ptr<Config> config;

		void runAt(uint64_t rva, int displacement = 0x20, bool withMapping = true)
		{
			clearAllStaticData();
			std::string ir = R"(
				@rsp = global i64 0
				@llvm2asm = global i64 0
				define void @fnc() {
				entry:
					store volatile i64 0, i64* @llvm2asm
					%sp = load i64, i64* @rsp
					%address = add i64 %sp, DISPLACEMENT
					%pointer = inttoptr i64 %address to i64*
					store i64 7, i64* %pointer
					ret void
				}
			)";
			auto displacementPos = ir.find("DISPLACEMENT");
			ir.replace(displacementPos, std::string("DISPLACEMENT").size(),
					std::to_string(displacement));
			parseInput(ir);
			auto* marker = getGlobalByName("llvm2asm");
			if (withMapping)
			{
				AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), marker);
				auto* markerStore = cast<StoreInst>(&getFunctionByName("fnc")->
						getEntryBlock().front());
				markerStore->setOperand(0, ConstantInt::get(
						Type::getInt64Ty(context), TraceBase + rva));
			}
			config = std::make_unique<Config>(Config::empty(module.get()));
			config->getConfig().functions.insert(retdec::common::Function("fnc"));
			config->getConfig().architecture.setName("x86-64");
			config->getConfig().architecture.setBitSize(64);
			config->getConfig().parameters.setGriffinSidecar(
					RETDEC_GRIFFIN_STACK_TEST_SIDECAR);
			auto* abi = AbiProvider::addAbi(module.get(), config.get());
			ASSERT_NE(nullptr, abi);
			auto* rsp = getGlobalByName("rsp");
			ASSERT_NE(nullptr, rsp);
			abi->addRegister(X86_REG_RSP, rsp);
			EXPECT_TRUE(abi->isStackPointerRegister(rsp));
			SymbolicTree::setAbi(abi);
			SymbolicTree::setConfig(config.get());
			StackAnalysis pass;
			pass.runOnModuleCustom(*module, config.get(), abi);
		}

		bool reconstructedFrame()
		{
			auto* fnc = getFunctionByName("fnc");
			return std::any_of(fnc->begin(), fnc->end(), [](BasicBlock& bb) {
				return std::any_of(bb.begin(), bb.end(), [](Instruction& inst) {
					return isa<AllocaInst>(inst);
				});
			});
		}
};

TEST_F(GriffinStackAnalysisTests, onlyExplicitAbiRoleRebuildsFrame)
{
	for (uint64_t rva : {0x1010, 0x1020, 0x1030, 0x1040, 0x1048, 0x1050,
			0x1060, 0x1068, 0x1070, 0x1078, 0x1080, 0x1090})
	{
		runAt(rva);
		EXPECT_FALSE(reconstructedFrame()) << std::hex << rva;
	}
	runAt(0x1000);
	EXPECT_TRUE(reconstructedFrame());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinStackAnalysisTests, abiRoleRequiresMatchingDisplacementAndAsmContext)
{
	runAt(0x1000, 0x28);
	EXPECT_FALSE(reconstructedFrame());

	runAt(0x1000, 0x20, false);
	EXPECT_FALSE(reconstructedFrame());
}

TEST_F(GriffinCffDecoderTests, provedStateSetBecomesSwitch)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %state) {
		entry:
			call void @__pseudo_br(i64 %state)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	ASSERT_TRUE(transform(TraceBase + 0x5000, pseudo));
	auto* sw = dyn_cast<SwitchInst>(entry->getTerminator());
	ASSERT_NE(nullptr, sw);
	EXPECT_EQ(2, sw->getNumCases());
	EXPECT_EQ(case7, sw->findCaseValue(ConstantInt::get(Type::getInt64Ty(context), 7))
			->getCaseSuccessor());
	EXPECT_TRUE(isa<UnreachableInst>(sw->getDefaultDest()->getTerminator()));
	EXPECT_FALSE(verifyModule(*module, &errs()));
	EXPECT_EQ(0, std::count_if(entry->begin(), entry->end(),
			[](const Instruction& i) { return isa<IndirectBrInst>(i); }));
	auto c = convertToC(*module);
	ASSERT_FALSE(c.empty());
	EXPECT_NE(std::string::npos, c.find("return 7")) << c;
	EXPECT_NE(std::string::npos, c.find("return 11")) << c;
}

TEST_F(GriffinCffDecoderTests, constantStateIsReducedToDirectBranch)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc() {
		entry:
			call void @__pseudo_br(i64 7)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	ASSERT_TRUE(transform(TraceBase + 0x5000, pseudo));
	auto* branch = dyn_cast<BranchInst>(entry->getTerminator());
	ASSERT_NE(nullptr, branch);
	EXPECT_TRUE(branch->isUnconditional());
	EXPECT_EQ(case7, branch->getSuccessor(0));
	EXPECT_EQ(0, std::count_if(entry->begin(), entry->end(),
			[](const Instruction& i) { return isa<SwitchInst>(i); }));
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinCffDecoderTests, completeReplayedSingletonBecomesDirectBranch)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %target) {
		entry:
			call void @__pseudo_br(i64 %target)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	ASSERT_TRUE(transform(TraceBase + 0xa010, pseudo));
	auto* branch = dyn_cast<BranchInst>(entry->getTerminator());
	ASSERT_NE(nullptr, branch);
	EXPECT_TRUE(branch->isUnconditional());
	EXPECT_EQ(case7, branch->getSuccessor(0));
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinCffDecoderTests, completeTargetSetWithoutStatesBecomesAddressSwitch)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %target) {
		entry:
			call void @__pseudo_br(i64 %target)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	ASSERT_TRUE(transform(TraceBase + 0x6000, pseudo));
	auto* sw = dyn_cast<SwitchInst>(entry->getTerminator());
	ASSERT_NE(nullptr, sw);
	ASSERT_EQ(2, sw->getNumCases());
	auto* int64Type = Type::getInt64Ty(context);
	EXPECT_EQ(case7, sw->findCaseValue(ConstantInt::get(
			int64Type, TraceBase + 0x3000))->getCaseSuccessor());
	EXPECT_EQ(case11, sw->findCaseValue(ConstantInt::get(
			int64Type, TraceBase + 0x4000))->getCaseSuccessor());
	EXPECT_TRUE(isa<UnreachableInst>(sw->getDefaultDest()->getTerminator()));
	EXPECT_EQ(0, std::count_if(entry->begin(), entry->end(),
			[](const Instruction& i) { return isa<IndirectBrInst>(i); }));
	EXPECT_FALSE(verifyModule(*module, &errs()));
	auto c = convertToC(*module);
	ASSERT_FALSE(c.empty());
	EXPECT_NE(std::string::npos, c.find("return 7")) << c;
	EXPECT_NE(std::string::npos, c.find("return 11")) << c;
}

TEST_F(GriffinCffDecoderTests, undefDestinationKeepsWholeSetUnchanged)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %state) {
		entry:
			call void @__pseudo_br(i64 %state)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 undef
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	auto before = printModule(*module);

	EXPECT_FALSE(transform(TraceBase + 0x5000, pseudo));
	EXPECT_EQ(before, printModule(*module));
	EXPECT_TRUE(isa<ReturnInst>(entry->getTerminator()));
	EXPECT_TRUE(case7->use_empty());
	EXPECT_TRUE(case11->use_empty());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinCffDecoderTests, missingDestinationNearCurrentBlockKeepsWholeSetUnchanged)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %state) {
		entry:
			call void @__pseudo_br(i64 %state)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	unregisterSecondTarget(case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	GriffinSidecar::ControlFlowTargetSet targetSet;
	targetSet.stateFromPseudoArgument = true;
	targetSet.targets.push_back({TraceBase + 0x3000, 7});
	targetSet.targets.push_back({TraceBase + 0x4000, 11});
	auto before = printModule(*module);

	EXPECT_FALSE(transformSet(TraceBase + 0x5000, pseudo, targetSet));
	EXPECT_EQ(before, printModule(*module));
	EXPECT_TRUE(isa<ReturnInst>(entry->getTerminator()));
	EXPECT_TRUE(case7->use_empty());
	EXPECT_TRUE(case11->use_empty());
	EXPECT_EQ(3, getFunctionByName("fnc")->size());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinCffDecoderTests, insufficientEvidenceFallbackSurvivesThroughC)
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %target) {
		entry:
			call void @__pseudo_br(i64 %target)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	auto before = printModule(*module);

	EXPECT_FALSE(transform(TraceBase + 0x7000, pseudo));
	EXPECT_EQ(before, printModule(*module));
	EXPECT_TRUE(isa<ReturnInst>(entry->getTerminator()));
	EXPECT_FALSE(verifyModule(*module, &errs()));
	auto c = convertToC(*module);
	ASSERT_FALSE(c.empty());
	EXPECT_NE(std::string::npos, c.find("__pseudo_br")) << c;
}

TEST_F(GriffinCffDecoderTests, incompleteOrBadReplayKeepsGenericTerminator)
{
	for (uint64_t site : {0x7000, 0x7010, 0x7020, 0x7030, 0x7040, 0x9000,
			0x9010, 0x9020, 0x9030, 0x9040, 0x9050, 0x9060, 0xa000, 0xa020})
	{
		parseInput(R"(
			declare void @__pseudo_br(i64)
			define i64 @fnc(i64 %target) {
			entry:
				call void @__pseudo_br(i64 %target)
				ret i64 0
			case7:
				ret i64 7
			case11:
				ret i64 11
			}
		)");
		prepareDecoder();
		llvm::BasicBlock *entry, *case7, *case11;
		registerTargets(entry, case7, case11);
		auto* pseudo = cast<CallInst>(&entry->front());
		EXPECT_FALSE(transform(TraceBase + site, pseudo));
		EXPECT_TRUE(isa<ReturnInst>(entry->getTerminator()));
		EXPECT_FALSE(verifyModule(*module, &errs()));
	}
}

void GriffinCffDecoderTests::lateUnsafeTargetDoesNotPartiallyMergeSet()
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %state) {
		entry:
			%upstream = add i64 %state, 0
			call void @__pseudo_br(i64 %upstream)
			ret i64 0
		}
		define i64 @target1() {
		entry:
			ret i64 7
		}
		define i64 @target2() {
		entry:
			%value = add i64 1, 2
			unreachable
		}
	)");
	prepareDecoder();
	auto* fnc = getFunctionByName("fnc");
	auto* target1 = getFunctionByName("target1");
	auto* target2 = getFunctionByName("target2");
	for (auto item : {
			std::pair<uint64_t, llvm::Function*>(0x3000, target1),
			{0x4000, target2}})
	{
		decoder._addr2fnc[TraceBase + item.first] = item.second;
		decoder._fnc2addr[item.second] = TraceBase + item.first;
		decoder._addr2bb[TraceBase + item.first] = &item.second->getEntryBlock();
		decoder._bb2addr[&item.second->getEntryBlock()] = TraceBase + item.first;
	}
	auto& entry = fnc->getEntryBlock();
	auto* pseudo = cast<CallInst>(entry.getTerminator()->getPrevNode());
	auto* upstream = &entry.front();
	ASSERT_TRUE(isa<BinaryOperator>(upstream));
	ASSERT_EQ(upstream, pseudo->getArgOperand(0));

	EXPECT_FALSE(transform(TraceBase + 0x5000, pseudo));
	EXPECT_TRUE(isa<ReturnInst>(entry.getTerminator()));
	EXPECT_EQ(upstream, &entry.front());
	EXPECT_EQ(upstream, pseudo->getArgOperand(0));
	EXPECT_EQ(target1, module->getFunction("target1"));
	EXPECT_EQ(target1, target1->getEntryBlock().getParent());
	EXPECT_EQ(target2, target2->getEntryBlock().getParent());
	EXPECT_EQ(4, module->getFunctionList().size());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

void GriffinCffDecoderTests::missingStateDoesNotPartiallyRewriteSet()
{
	parseInput(R"(
		declare void @__pseudo_br(i64)
		define i64 @fnc(i64 %state) {
		entry:
			call void @__pseudo_br(i64 %state)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	auto targetSet = decoder._griffin->getControlTargetSet(
			TraceBase + 0x5000, "jmp");
	ASSERT_TRUE(targetSet);
	ASSERT_EQ(2, targetSet->targets.size());
	targetSet->targets[1].stateValue.reset();

	EXPECT_FALSE(decoder.transformToGriffinControlFlowSet(
			TraceBase + 0x5000, pseudo, TraceBase + 0x5005, *targetSet));
	EXPECT_TRUE(isa<ReturnInst>(entry->getTerminator()));
	EXPECT_EQ(case7->getParent(), case11->getParent());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinCffDecoderTests, lateUnsafeTargetDoesNotPartiallyMergeSet)
{
	lateUnsafeTargetDoesNotPartiallyMergeSet();
}

TEST_F(GriffinCffDecoderTests, missingStateDoesNotPartiallyRewriteSet)
{
	missingStateDoesNotPartiallyRewriteSet();
}

TEST_F(GriffinCffDecoderTests, outOfRangeStateCasesKeepGenericTerminator)
{
	parseInput(R"(
		declare void @__pseudo_br(i8)
		define i64 @fnc(i8 %state) {
		entry:
			call void @__pseudo_br(i8 %state)
			ret i64 0
		case7:
			ret i64 7
		case11:
			ret i64 11
		}
	)");
	prepareDecoder();
	llvm::BasicBlock *entry, *case7, *case11;
	registerTargets(entry, case7, case11);
	auto* pseudo = cast<CallInst>(&entry->front());
	GriffinSidecar::ControlFlowTargetSet targetSet;
	targetSet.stateFromPseudoArgument = true;
	targetSet.targets.push_back({TraceBase + 0x3000, 0x100});
	targetSet.targets.push_back({TraceBase + 0x4000, 0x101});
	auto blockCount = getFunctionByName("fnc")->size();

	EXPECT_FALSE(transformSet(TraceBase + 0x5000, pseudo, targetSet));
	EXPECT_TRUE(isa<ReturnInst>(entry->getTerminator()));
	EXPECT_EQ(blockCount, getFunctionByName("fnc")->size());
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

TEST_F(GriffinCffDecoderTests, overlappedTargetSetKeepsCoverageForEveryTarget)
{
	checkOverlappedTargets();
}

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

TEST_F(GriffinDecoderTests, rejectedAndScratchControlsLeaveModuleUnchanged)
{
	rejectedAndScratchControlsLeaveModuleUnchanged();
}

TEST_F(GriffinDecoderTests, provedJumpMergesPlaceholderWithoutCall)
{
	provedJumpMergesPlaceholderWithoutCall();
}

TEST_F(GriffinDecoderTests, unsafeJumpTargetDoesNotBecomeCall)
{
	unsafeJumpTargetDoesNotBecomeCall();
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
