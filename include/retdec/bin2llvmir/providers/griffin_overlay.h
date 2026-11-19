/**
* @file include/retdec/bin2llvmir/providers/griffin_overlay.h
* @brief Opt-in application of validated dynamic bytes for Griffin analysis.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_GRIFFIN_OVERLAY_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_GRIFFIN_OVERLAY_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "retdec/loader/loader/image.h"

namespace retdec {
namespace bin2llvmir {

/** Dynamic-byte overlay applied only to an in-memory analysis image. */
class GriffinOverlay
{
	public:
		static GriffinOverlay fromFile(const std::string& path);

		bool checkImageSha256(const std::string& actualSha256) const;
		std::size_t applyTo(loader::Image& image, uint64_t imageBase) const;
		std::optional<uint64_t> getRequiredEnd(uint64_t rva) const;
		std::optional<uint64_t> getRequiredRangeEnd(
				uint64_t startRva,
				uint64_t currentEndRva) const;
		std::optional<std::pair<uint64_t, uint64_t>> getExecutedBounds(
				uint64_t startAddress,
				uint64_t endAddress) const;
		std::vector<uint64_t> getEntryStarts(
				uint64_t startAddress,
				uint64_t endAddress) const;

		std::size_t getEntryCount() const;
		std::size_t getAppliedByteCount() const;
		std::size_t getConflictCount() const;

	private:
		struct Entry
		{
			std::vector<std::uint8_t> data;
		};
		struct ObservedRange
		{
			uint64_t startRva;
			uint64_t endRva;
		};

		std::vector<uint64_t> _bases;
		uint64_t _imageSize = 0;
		std::string _imageSha256;
		std::map<uint64_t, Entry> _entries;
		std::vector<ObservedRange> _observedRanges;
		std::set<uint64_t> _conflicts;
		std::map<uint64_t, std::uint8_t> _uniqueBytes;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
