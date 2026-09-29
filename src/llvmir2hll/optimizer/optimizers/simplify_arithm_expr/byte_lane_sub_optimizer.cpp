/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/byte_lane_sub_optimizer.cpp
* @brief Implementation of ByteLaneSubOptimizer.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/byte_lane_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("ByteLane", BYTE_LANE_SUB_OPTIMIZER_ID, SubOptimizerFactory,
	ByteLaneSubOptimizer::create);

namespace {

/**
* @brief If @a expr is `X & C` with @a C a ConstInt, returns X and stores the
*        mask; otherwise returns the null pointer.
*/
ShPtr<Expression> matchAndConst(ShPtr<Expression> expr, ShPtr<ConstInt>& mask) {
	ShPtr<BitAndOpExpr> andExpr(cast<BitAndOpExpr>(expr));
	if (!andExpr) {
		return ShPtr<Expression>();
	}

	if (ShPtr<ConstInt> c = cast<ConstInt>(andExpr->getSecondOperand())) {
		mask = c;
		return andExpr->getFirstOperand();
	}
	if (ShPtr<ConstInt> c = cast<ConstInt>(andExpr->getFirstOperand())) {
		mask = c;
		return andExpr->getSecondOperand();
	}
	return ShPtr<Expression>();
}

} // anonymous namespace

/**
* @brief Constructs the ByteLaneSubOptimizer.
*/
ByteLaneSubOptimizer::ByteLaneSubOptimizer(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Creates a new ByteLaneSubOptimizer.
*/
ShPtr<SubOptimizer> ByteLaneSubOptimizer::create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new ByteLaneSubOptimizer(arithmExprEvaluator));
}

std::string ByteLaneSubOptimizer::getId() const {
	return BYTE_LANE_SUB_OPTIMIZER_ID;
}

void ByteLaneSubOptimizer::visit(ShPtr<BitOrOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	ShPtr<ConstInt> maskA;
	ShPtr<ConstInt> maskB;
	ShPtr<Expression> valA(matchAndConst(expr->getFirstOperand(), maskA));
	ShPtr<Expression> valB(matchAndConst(expr->getSecondOperand(), maskB));

	// Both sides must be `value & const` over the SAME value.
	if (!valA || !valB || !valA->isEqualTo(valB)) {
		return;
	}

	// Merge the masks: (v & c1) | (v & c2) -> v & (c1 | c2).
	// Semantically exact for any two constant masks, overlapping or disjoint.
	llvm::APSInt a(maskA->getValue());
	llvm::APSInt b(maskB->getValue());
	if (a.getBitWidth() != b.getBitWidth()) {
		return;
	}
	llvm::APSInt merged(a | b, a.isUnsigned());

	// If the merged mask is all-ones, the whole `and` is the identity: the OR
	// covered every bit of the value, so `(v & c1) | (v & c2)` is just `v`.
	if (merged.isAllOnesValue()) {
		optimizeExpr(expr, valA);
		return;
	}

	ShPtr<BitAndOpExpr> newExpr(BitAndOpExpr::create(
		valA,
		ConstInt::create(merged)));
	optimizeExpr(expr, newExpr);
}

} // namespace llvmir2hll
} // namespace retdec
