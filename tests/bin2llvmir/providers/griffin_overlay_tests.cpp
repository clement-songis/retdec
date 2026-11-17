/**
* @file tests/bin2llvmir/providers/griffin_overlay_tests.cpp
* @brief Focused tests for opt-in Griffin dynamic-byte overlays.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <cstdlib>
#include <map>
#include <vector>

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/providers/griffin_overlay.h"

using namespace ::testing;

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

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
