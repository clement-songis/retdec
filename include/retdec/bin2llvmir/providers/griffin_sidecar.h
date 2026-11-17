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
		static GriffinSidecar fromFile(const std::string& path);

		std::optional<common::Address> getRetTrampolineTarget(
				common::Address site) const;

		std::size_t getRetTargetCount() const;
		std::size_t getUnresolvedRetCount() const;

	private:
		std::vector<uint64_t> _bases;
		uint64_t _imageSize = 0;
		std::map<uint64_t, uint64_t> _retTargets;
		std::set<uint64_t> _unresolvedRets;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
