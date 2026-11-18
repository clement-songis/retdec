/**
* @file include/retdec/bin2llvmir/analyses/nt_wdk_prototypes.h
* @brief Official NT/WDK prototypes for known external declarations.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_NT_WDK_PROTOTYPES_H
#define RETDEC_BIN2LLVMIR_ANALYSES_NT_WDK_PROTOTYPES_H

#include <cstddef>
#include <llvm/IR/Module.h>

namespace retdec {
namespace bin2llvmir {

/** Generic Microsoft WDK type knowledge; independent of Griffin providers. */
class NtWdkPrototypes
{
	public:
		/// Refine known external declarations and preserve old uses by bitcast.
		static std::size_t apply(llvm::Module& module);
};

} // namespace bin2llvmir
} // namespace retdec

#endif
