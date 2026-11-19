/**
* @file tests/bin2llvmir/providers/griffin_overlay_tests.cpp
* @brief Focused tests for opt-in Griffin dynamic-byte overlays.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <cstdlib>
#include <map>
#include <vector>

#include <llvm/IR/InstIterator.h>

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder_ranges.h"
#include "retdec/bin2llvmir/optimizations/value_protect/value_protect.h"
#include "retdec/bin2llvmir/providers/abi/x86.h"
#include "retdec/bin2llvmir/providers/griffin_overlay.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {
namespace {

constexpr uint64_t TraceBase = 0x140000000;
constexpr const char* VgkSha = "c8ca7db29692b5e5317c66f980ea45b868cb28466edd5e57d9439cceee88e390";

class OverlayImageMock : public loader::Image
{
	public:
		OverlayImageMock() : loader::Image(nullptr) {}

		bool load() override { return true; }

		bool setXBytes(uint64_t address, const std::vector<std::uint8_t>& data) override
		{
			writes[address] = data;
			return true;
		}

		std::map<uint64_t, std::vector<std::uint8_t>> writes;
};

std::vector<std::uint8_t> bytes(std::initializer_list<std::uint8_t> input)
{
	return std::vector<std::uint8_t>(input);
}

} // namespace

class GriffinOverlayTests: public LlvmIrTests
{
};

TEST_F(GriffinOverlayTests, realOverlayAppliesWitnessBytesAtImageBase)
{
	const char* path = std::getenv("RETDEC_GRIFFIN_OVERLAY");
	if (path == nullptr)
	{
		GTEST_SKIP() << "RETDEC_GRIFFIN_OVERLAY not set";
	}
	auto overlay = GriffinOverlay::fromFile(path);
	OverlayImageMock image;

	EXPECT_TRUE(overlay.checkImageSha256(VgkSha));
	EXPECT_FALSE(overlay.checkImageSha256(std::string(64, '0')));
	EXPECT_EQ(66, overlay.getEntryCount());
	EXPECT_EQ(298, overlay.getAppliedByteCount());
	EXPECT_EQ(0, overlay.getConflictCount());
	EXPECT_EQ(66, overlay.applyTo(image, TraceBase));
	EXPECT_EQ(66, image.writes.size());
	EXPECT_EQ(bytes({0xe8, 0x9e, 0x5d, 0xe4, 0xff}), image.writes[TraceBase + 0x463ade]);
	EXPECT_EQ(bytes({0x53}), image.writes[TraceBase + 0x2a9881]);
	EXPECT_EQ(bytes({0x48, 0x83, 0xec, 0x20}), image.writes[TraceBase + 0x2a9882]);
	EXPECT_EQ(bytes({0x48, 0x8b, 0xd9}), image.writes[TraceBase + 0x2a9886]);
	EXPECT_EQ(bytes({0xff, 0xe0}), image.writes[TraceBase + 0x58df90]);
	EXPECT_EQ(bytes({0xc3}), image.writes[TraceBase + 0x569140]);
	EXPECT_EQ(0x463ae3, *overlay.getRequiredRangeEnd(0x463ade, 0x463ae2));
	EXPECT_EQ(0x2a9889, *overlay.getRequiredRangeEnd(0x2a9881, 0x2a9888));
	EXPECT_EQ(0x58df92, *overlay.getRequiredRangeEnd(0x58df90, 0x58df91));
	EXPECT_EQ(0x569141, *overlay.getRequiredRangeEnd(0x569140, 0x569140));
}

TEST_F(GriffinOverlayTests, conflictsAndIneligibleEntriesAreNotApplied)
{
	auto overlay = GriffinOverlay::fromFile(RETDEC_GRIFFIN_OVERLAY_TEST);
	OverlayImageMock image;

	EXPECT_EQ(1, overlay.getEntryCount());
	EXPECT_EQ(5, overlay.getAppliedByteCount());
	EXPECT_EQ(1, overlay.getConflictCount());
	EXPECT_EQ(1, overlay.applyTo(image, TraceBase));
	EXPECT_EQ(1, image.writes.size());
	EXPECT_EQ(bytes({0xe8, 0x9e, 0x5d, 0xe4, 0xff}), image.writes[TraceBase + 0x463ade]);
	EXPECT_EQ(0, image.writes.count(TraceBase + 0x58df90));
	EXPECT_EQ(0, image.writes.count(TraceBase + 0xdead));
	EXPECT_THROW(overlay.applyTo(image, 0x1234), std::runtime_error);
}

TEST_F(GriffinOverlayTests, overlappingDifferentBytesAreRejected)
{
	EXPECT_THROW(
			GriffinOverlay::fromFile(RETDEC_GRIFFIN_OVERLAY_CONFLICT_TEST),
			std::runtime_error);
}

TEST_F(GriffinOverlayTests, nonExecutedPrefixYieldsToFirstProvenBoundary)
{
	auto overlay = GriffinOverlay::fromFile(RETDEC_GRIFFIN_OVERLAY_BOUNDARIES_TEST);
	OverlayImageMock image;
	auto bounds = overlay.getExecutedBounds(TraceBase + 0x8000, TraceBase + 0x8070);

	ASSERT_TRUE(bounds);
	EXPECT_EQ(TraceBase + 0x8001, bounds->first);
	EXPECT_EQ(TraceBase + 0x8004, bounds->second);
	EXPECT_FALSE(overlay.getRequiredEnd(0x8000));
	EXPECT_EQ(2, overlay.applyTo(image, TraceBase));
	EXPECT_EQ(0, image.writes.count(TraceBase + 0x8000));
	EXPECT_EQ(bytes({0x90}), image.writes[TraceBase + 0x8001]);
	EXPECT_EQ(std::vector<uint64_t>({TraceBase + 0x8001}),
			overlay.getEntryStarts(TraceBase + 0x8000, TraceBase + 0x8002));
	auto firstOnly = overlay.getExecutedBounds(TraceBase + 0x8000, TraceBase + 0x8001);
	ASSERT_TRUE(firstOnly);
	EXPECT_EQ(TraceBase + 0x8001, firstOnly->first);
	EXPECT_EQ(TraceBase + 0x8002, firstOnly->second);
}

TEST_F(GriffinOverlayTests, staticOnlyTailIsExplicitlyGuarded)
{
	auto overlay = GriffinOverlay::fromFile(RETDEC_GRIFFIN_OVERLAY_BOUNDARIES_TEST);

	EXPECT_EQ(110, overlay.getNonExecutedBoundaryByteCount());
	EXPECT_TRUE(overlay.isNonExecuted(TraceBase + 0x8000));
	EXPECT_FALSE(overlay.isNonExecuted(TraceBase + 0x8001));
	EXPECT_FALSE(overlay.isNonExecuted(TraceBase + 0x8003));
	EXPECT_TRUE(overlay.isNonExecuted(TraceBase + 0x8004));
	EXPECT_TRUE(overlay.isNonExecuted(TraceBase + 0x8070));
	EXPECT_FALSE(overlay.isNonExecuted(TraceBase + 0x8071));
}

TEST_F(GriffinOverlayTests, rangeExtensionPreservesAlternativeDecoding)
{
	RangesToDecode ranges;
	ranges.addPrimary(0x1000, 0x1002);
	ranges.addAlternative(0x1001, 0x1003);

	ranges.removePrimary(0x1000, 0x1002);

	EXPECT_EQ(nullptr, ranges.getPrimary(0x1000));
	auto* alternative = ranges.getAlternative(0x1001);
	ASSERT_NE(nullptr, alternative);
	EXPECT_EQ(0x1001, alternative->getStart());
	EXPECT_EQ(0x1003, alternative->getEnd());

	ranges.removeAlternative(0x1001, 0x1003);
	EXPECT_EQ(nullptr, ranges.getAlternative(0x1001));
}

TEST_F(GriffinOverlayTests, volatileStackStoreSurvivesValueProtectUnprotect)
{
	parseInput(R"(
		define i64 @fnc() {
		entry:
			%stack_var = alloca i64
			ret i64 0
		}
	)");
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);
	ValueProtect pass;

	ASSERT_TRUE(pass.runOnModuleCustom(*module, &c, &abi));
	auto* fnc = getFunctionByName("fnc");
	StoreInst* protectedStore = nullptr;
	for (auto& instruction : instructions(fnc))
	{
		if (auto* store = dyn_cast<StoreInst>(&instruction))
		{
			protectedStore = store;
		}
	}
	ASSERT_NE(nullptr, protectedStore);
	protectedStore->setVolatile(true);

	ASSERT_TRUE(pass.runOnModuleCustom(*module, &c, &abi));
	bool found = false;
	for (auto& instruction : instructions(fnc))
	{
		if (auto* store = dyn_cast<StoreInst>(&instruction);
				store && store->isVolatile())
		{
			found = true;
		}
	}
	EXPECT_TRUE(found);
	EXPECT_FALSE(verifyModule(*module, &errs()));
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
