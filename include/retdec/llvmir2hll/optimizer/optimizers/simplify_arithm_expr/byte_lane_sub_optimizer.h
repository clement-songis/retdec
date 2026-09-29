/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/byte_lane_sub_optimizer.h
* @brief A sub-optimization class that merges masked byte lanes of one value.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_BYTE_LANE_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_BYTE_LANE_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief TIER-1 PASS 3: merges masked byte lanes of the SAME value.
*
* Griffin re-assembles a word from masked lanes of one value, producing verbose
* mask chains in the decompiled C. This optimizer contracts them:
*
* @par Same-value masked lanes
* @code
* return v & -256 | v & 255;   // two masks over the same v
* @endcode
* is optimized to
* @code
* return v & -1;               // and then the & -1 is dropped elsewhere -> v
* @endcode
* i.e. `(v & c1) | (v & c2)` becomes `v & (c1 | c2)` (either operand order,
* and the shape may appear as the left or right child of a longer OR chain).
*
* This is always semantically exact for constant masks, regardless of whether
* the masks overlap or are disjoint. It removes one `and` and one `or` node and
* one hex constant per hit.
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class ByteLaneSubOptimizer final: public SubOptimizer {
public:
	ByteLaneSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<BitOrOpExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
