/**
* @file include/retdec/bin2llvmir/providers/griffin_sidecar.h
* @brief Validated Griffin dynamic control-flow evidence.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_GRIFFIN_SIDECAR_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_GRIFFIN_SIDECAR_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "retdec/common/address.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Read-only provider for ret-trampolines proved by a dynamic sidecar.
 *
 * A plain ret with an observed successor is not enough: it may be an ordinary
 * function return. We require both stack-trampoline evidence and a successor
 * proof. Addresses are joined by RVA and converted back using the site's base.
 */
class GriffinSidecar
{
	public:
		enum class StackSlotRole
		{
			Unknown,
			AbiFrame,
			VmRegister,
			VmSpill
		};

		struct StackSlot
		{
			int64_t displacement = 0;
			uint64_t address = 0;
			uint64_t size = 0;
			StackSlotRole role = StackSlotRole::Unknown;
		};

		enum class ControlStatus
		{
			Unknown,
			Proven,
			Rejected
		};

		static GriffinSidecar fromFile(const std::string& path);

		ControlStatus getControlStatus(
				common::Address site,
				const std::string& kind) const;
		std::optional<common::Address> getControlTarget(
				common::Address site,
				const std::string& kind) const;
		std::optional<common::Address> getRetTrampolineTarget(
				common::Address site) const;
		std::optional<StackSlot> getStackSlot(common::Address site) const;

		bool checkImageSha256(const std::string& actualSha256) const;
		bool isEvidenceV2() const;
		std::size_t getControlTargetCount() const;
		std::size_t getDynamicVerifiedTargetCount() const;
		std::size_t getRetTargetCount() const;
		std::size_t getUnresolvedRetCount() const;
		std::size_t getStackSlotCount() const;
		std::size_t getAbiFrameStackSlotCount() const;

	private:
		struct ControlTarget
		{
			uint64_t targetRva = 0;
			std::string kind;
			std::string classification;
		};

		std::optional<common::Address> getTarget(
				common::Address site,
				const std::string& kind) const;

		std::vector<uint64_t> _bases;
		uint64_t _imageSize = 0;
		bool _evidenceV2 = false;
		std::string _imageSha256;
		std::map<uint64_t, ControlTarget> _controlTargets;
		std::map<uint64_t, std::string> _rejectedControlTargets;
		std::size_t _dynamicVerifiedTargetCount = 0;
		std::map<uint64_t, uint64_t> _retTargets;
		std::set<uint64_t> _unresolvedRets;
		std::map<uint64_t, StackSlot> _stackSlots;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
