/**
 * @file src/bin2llvmir/optimizations/inst_opt/inst_opt.cpp
 * @brief Optimize a single LLVM instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"
#include "retdec/bin2llvmir/utils/debug.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {
namespace inst_opt {

/**
 * x = add y, 0
 *   =>
 * x = y
 *
 * x = add 0, y
 *   =>
 * x = y
 */
bool addZero(llvm::Instruction* insn)
{
	Value* val;
	uint64_t zero;

	if (!(match(insn, m_Add(m_Value(val), m_ConstantInt(zero)))
			|| match(insn, m_Add(m_ConstantInt(zero), m_Value(val)))))
	{
		return false;
	}
	if (zero != 0)
	{
		return false;
	}

	insn->replaceAllUsesWith(val);
	insn->eraseFromParent();
	return true;
}

/**
 * x = sub y, 0
 *   =>
 * x = use y
 */
bool subZero(llvm::Instruction* insn)
{
	uint64_t zero;

	if (!match(insn, m_Sub(m_Value(), m_ConstantInt(zero))))
	{
		return false;
	}
	if (zero != 0)
	{
		return false;
	}

	insn->replaceAllUsesWith(insn->getOperand(0));
	insn->eraseFromParent();
	return true;
}

/**
 * a = trunc i32 val to i8
 * b = zext i8 a to i32
 *   =>
 * b = and i32 val, 255
 *
 * a = trunc i32 val to i16
 * b = zext i16 a to i32
 *   =>
 * b = and i32 val, 65535
 */
bool truncZext(llvm::Instruction* insn)
{
	Value* val;

	if (!match(insn, m_ZExt(m_Trunc(m_Value(val)))))
	{
		return false;
	}
	auto* zext = cast<ZExtInst>(insn);
	auto* trunc = cast<TruncInst>(zext->getOperand(0));
	Instruction* a = nullptr;

	if (trunc->getSrcTy()->isIntegerTy(32)
		&& trunc->getDestTy()->isIntegerTy(8)
		&& zext->getSrcTy()->isIntegerTy(8)
		&& zext->getDestTy()->isIntegerTy(32))
	{
		a = BinaryOperator::CreateAnd(
				val,
				ConstantInt::get(val->getType(), 255),
				"",
				zext);
	}
	else if (trunc->getSrcTy()->isIntegerTy(32)
			&& trunc->getDestTy()->isIntegerTy(16)
			&& zext->getSrcTy()->isIntegerTy(16)
			&& zext->getDestTy()->isIntegerTy(32))
	{
		a = BinaryOperator::CreateAnd(
				val,
				ConstantInt::get(val->getType(), 65535),
				"",
				zext);
	}
	if (a == nullptr)
	{
		return false;
	}

	a->takeName(zext);
	zext->replaceAllUsesWith(a);
	zext->eraseFromParent();
	if (trunc->user_empty())
	{
		trunc->eraseFromParent();
	}

	return true;
}

/**
 * a = xor x, x
 *   =>
 * a = 0
 */
bool xorXX(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_Xor(m_Value(op0), m_Value(op1)))
			&& op0 == op1))
	{
		return false;
	}

	insn->replaceAllUsesWith(ConstantInt::get(insn->getType(), 0));
	insn->eraseFromParent();

	return true;
}

/**
 * a = load x
 * b = load x
 * c = xor a, b
 *   =>
 * c = 0
 */
bool xorLoadXX(llvm::Instruction* insn)
{
	Instruction* i1;
	Instruction* i2;

	if (!(match(insn, m_Xor(m_Instruction(i1), m_Instruction(i2)))
			&& isa<LoadInst>(i1)
			&& isa<LoadInst>(i2)))
	{
		return false;
	}
	LoadInst* l1 = cast<LoadInst>(i1);
	LoadInst* l2 = cast<LoadInst>(i2);
	if (l1->getPointerOperand() != l2->getPointerOperand())
	{
		return false;
	}

	insn->replaceAllUsesWith(ConstantInt::get(insn->getType(), 0));
	insn->eraseFromParent();
	if (l1->user_empty())
	{
		l1->eraseFromParent();
	}
	if (l2 != l1 && l2->user_empty())
	{
		l2->eraseFromParent();
	}

	return true;
}

/**
 * a = or x, x
 *   =>
 * a = x
 *
 * a = and x, x
 *   =>
 * a = x
 */
bool orAndXX(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_Or(m_Value(op0), m_Value(op1)))
			|| match(insn, m_And(m_Value(op0), m_Value(op1)))))
	{
		return false;
	}
	if (op0 != op1)
	{
		return false;
	}

	insn->replaceAllUsesWith(op0);
	insn->eraseFromParent();

	return true;
}

/**
 * a = load x
 * b = load x
 * c = or a, b
 *   =>
 * c = 0
 *
 * a = load x
 * b = load x
 * c = and a, b
 *   =>
 * c = 0
 */
bool orAndLoadXX(llvm::Instruction* insn)
{
	Instruction* i1;
	Instruction* i2;

	if (!(match(insn, m_Or(m_Instruction(i1), m_Instruction(i2)))
			|| match(insn, m_And(m_Instruction(i1), m_Instruction(i2)))))
	{
		return false;
	}
	LoadInst* l1 = dyn_cast<LoadInst>(i1);
	LoadInst* l2 = dyn_cast<LoadInst>(i2);
	if (l1 == nullptr
			|| l2 == nullptr
			|| l1->getPointerOperand() != l2->getPointerOperand())
	{
		return false;
	}

	insn->replaceAllUsesWith(l1);
	insn->eraseFromParent();
	if (l2->user_empty())
	{
		l2->eraseFromParent();
	}

	return true;
}

/**
 * a = xor i1 x, y
 *   =>
 * a = icmp ne i1 x, y
 */
bool xor_i1(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_Xor(m_Value(op0), m_Value(op1)))
			&& insn->getType()->isIntegerTy(1)))
	{
		return false;
	}

	auto* cmp = CmpInst::Create(
			Instruction::ICmp,
			ICmpInst::ICMP_NE,
			op0,
			op1,
			"",
			insn);
	cmp->takeName(insn);
	insn->replaceAllUsesWith(cmp);
	insn->eraseFromParent();

	return true;
}

/**
 * a = and i1 x, y
 *   =>
 * a = icmp eq i1 x, y
 */
bool and_i1(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_And(m_Value(op0), m_Value(op1)))
			&& insn->getType()->isIntegerTy(1)))
	{
		return false;
	}

	auto* cmp = CmpInst::Create(
			Instruction::ICmp,
			ICmpInst::ICMP_EQ,
			op0,
			op1,
			"",
			insn);
	cmp->takeName(insn);
	insn->replaceAllUsesWith(cmp);
	insn->eraseFromParent();

	return true;
}

/**
 * a = add x, c1
 * b = add a, c2
 *   =>
 * b = add x, (c1 + c2)
 */
bool addSequence(llvm::Instruction* insn)
{
	Value* val;
	ConstantInt* c1;
	ConstantInt* c2;

	if (!(match(insn, m_Add(
			m_Add(m_Value(val), m_ConstantInt(c1)),
			m_ConstantInt(c2)))))
	{
		return false;
	}

	Instruction* secondAdd = cast<Instruction>(insn->getOperand(0));
	insn->setOperand(0, val);
	insn->setOperand(1, ConstantInt::get(insn->getType(), c1->getValue() + c2->getValue()));

	if (secondAdd->user_empty())
	{
		secondAdd->eraseFromParent();
	}

	return true;
}

/**
 * cast1 fp/ptr to ...
 * ...
 * cast2 ... to fp/ptr
 *   =>
 * cast fp/ptr to fp/ptr
 *
 * Do not do this for integers. It is not always safe.
 * E.g. i32 -> i1 -> i32 is not the same as i32 -> i32.
 * It may not be safe for pointers and floats as well, but we leave it for now.
 */
llvm::Value* castSequence(llvm::CastInst* cast1, llvm::CastInst* cast2)
{
	auto* src = cast1->getOperand(0);
	auto* srcTy = cast1->getSrcTy();
	auto* dstTy = cast2->getDestTy();

	Value* v = nullptr;

	if (srcTy->isPointerTy() && dstTy->isPointerTy())
	{
		v = srcTy != dstTy
				? CastInst::CreatePointerCast(src, dstTy, "", cast2)
				: src;
	}
	// float -> cast -> cast -> float
	else if (srcTy->isFloatingPointTy() && dstTy->isFloatingPointTy())
	{
		v = srcTy != dstTy
				? CastInst::CreateFPCast(src, dstTy, "", cast2)
				: src;
	}
	else
	{
		return nullptr;
	}

	cast2->replaceAllUsesWith(v);
	cast2->eraseFromParent();
	if (cast1->user_empty())
	{
		cast1->eraseFromParent();
	}
	return v;
}

/**
 * Find cast sequnces to try to optimize.
 */
llvm::Value* castSequenceFinder(llvm::Value* insn)
{
	auto* cast2 = dyn_cast<CastInst>(insn);
	auto* cast1 = cast2 ? dyn_cast<CastInst>(cast2->getOperand(0)) : nullptr;

	while (cast1)
	{
		if (auto* v = castSequence(cast1, cast2))
		{
			return v;
		}
		cast1 = dyn_cast<CastInst>(cast1->getOperand(0));
	}

	return nullptr;
}

/**
 * Apply cast optimization repeatedly until it can not be applied anymore.
 */
bool castSequenceWrapper(llvm::Instruction* insn)
{
	bool changed = false;
	Value* v = insn;
	while (v)
	{
		v = castSequenceFinder(v);
		changed |= v != nullptr;
	}
	return changed;
}

/**
 * \code{.ll}
 * store float %val, float* bitcast (i32* @gv to float*)
 *   ==>
 * %conv = bitcast float %val to i32
 * store i32 %conv, i32* @gv
 * \endcode
 *
 * This is countering an undesirable LLVM instrcombine optimization
 * that is going the other way.
 */
bool storeToBitcastPointer(llvm::Instruction* insn)
{
	Value* val;
	Value* op;
	if (!match(insn, m_Store(m_Value(val), m_BitCast(m_Value(op))))
			|| !op->getType()->getPointerElementType()->isFirstClassType()
			|| op->getType()->getPointerElementType()->isAggregateType()
			|| op->getType()->getPointerElementType()->isPointerTy())
	{
		return false;
	}

	if (!BitCastInst::isBitCastable(
			val->getType(),
			op->getType()->getPointerElementType()))
	{
		return false;
	}

	auto* conv = CastInst::CreateBitOrPointerCast(
			val,
			op->getType()->getPointerElementType(),
			"",
			insn);
	new StoreInst(conv, op, insn);

	auto* bitcastI = dyn_cast<BitCastInst>(insn->getOperand(1));
	auto* bitcastCE = dyn_cast<ConstantExpr>(insn->getOperand(1));
	insn->eraseFromParent();
	if (bitcastI && bitcastI->use_empty())
	{
		bitcastI->eraseFromParent();
	}
	if (bitcastCE && bitcastCE->use_empty())
	{
		bitcastCE->destroyConstant();
	}

	return true;
}

/**
 * \code{.ll}
 * %1 = load float, float* bitcast (i32* @g to float*)
 *   ==>
 * %1 = load i32, i32* @g
 * %2 = bitcast i32 %1 to float
 *
 * %1 = load i8*, i8** bitcast (i32* @g to i8**)
 *   ==>
 * %1 = load i32, i32* @g
 * %2 = inttoptr i32 %1 to i8*
 * \endcode
 */
bool loadFromBitcastPointer(llvm::Instruction* insn)
{
	Value* op;
	if (!match(insn, m_Load(m_BitCast(m_Value(op))))
			|| !op->getType()->getPointerElementType()->isFirstClassType()
			|| op->getType()->getPointerElementType()->isAggregateType())
	{
		return false;
	}

	if (!BitCastInst::isBitOrNoopPointerCastable(
			op->getType()->getPointerElementType(),
			insn->getType(),
			insn->getModule()->getDataLayout()))
	{
		return false;
	}

	auto* l = new LoadInst(op, "", insn);
	l->setAlignment(cast<LoadInst>(insn)->getAlignment());
	auto* conv = CastInst::CreateBitOrPointerCast(l, insn->getType(), "", insn);
	insn->replaceAllUsesWith(conv);

	auto* bitcastI = dyn_cast<BitCastInst>(insn->getOperand(0));
	auto* bitcastCE = dyn_cast<ConstantExpr>(insn->getOperand(0));

	insn->eraseFromParent();
	if (bitcastI && bitcastI->use_empty())
	{
		bitcastI->eraseFromParent();
	}
	if (bitcastCE && bitcastCE->use_empty())
	{
		bitcastCE->destroyConstant();
	}

	return true;
}

//=============================================================================
// TIER-1 readability passes (RE Vanguard fork).
//
// PASS 1 - Mixed Boolean-Arithmetic (MBA) simplification.
//
// Griffin obfuscation rewrites plain `a^b`, `a+b`, `a` as verbose MBA forms.
// LLVM's instcombine already folds the simplest of these on clean code, but on
// lifted obfuscated IR the sub-expressions are split across many SSA temps and
// interleaved with flag/trunc calculations, so instcombine's local matcher
// misses them. inst_opt runs to a fixed point from the RDA loop, so it catches
// them once neighbouring passes have normalised the operands.
//
// Every identity below was verified by exhaustive 8-bit truth table before
// being coded (see docs / session log). All operate on values (SSA), so they
// are width-agnostic: the rewrite reuses the operands' own type.
//=============================================================================

/// Replace \p insn by value \p v, take its name, erase it.
static bool replaceWith(llvm::Instruction* insn, llvm::Value* v)
{
	if (auto* i = dyn_cast<Instruction>(v))
	{
		i->takeName(insn);
	}
	insn->replaceAllUsesWith(v);
	insn->eraseFromParent();
	return true;
}

/**
 * MBA XOR, subtractive form:
 *
 * x = (a | b) - (a & b)
 *   =>
 * x = a ^ b
 *
 * The and/or must be over the SAME pair of operands (in either order).
 */
bool mbaXorSubOrAnd(llvm::Instruction* insn)
{
	Value* o0; Value* o1;
	Value* a0; Value* a1;

	if (!match(insn, m_Sub(
			m_Or(m_Value(o0), m_Value(o1)),
			m_And(m_Value(a0), m_Value(a1)))))
	{
		return false;
	}
	if (!((o0 == a0 && o1 == a1) || (o0 == a1 && o1 == a0)))
	{
		return false;
	}

	auto* x = BinaryOperator::CreateXor(o0, o1, "", insn);
	return replaceWith(insn, x);
}

/**
 * MBA XOR, "a + b - 2*(a & b)" form. This one survives instcombine.
 *
 * x = (a + b) - 2 * (a & b)      // 2*(a&b) may be `mul (a&b), 2` or `shl (a&b), 1`
 *   =>
 * x = a ^ b
 */
bool mbaXorAddSub(llvm::Instruction* insn)
{
	Value* s0; Value* s1;
	if (!match(insn, m_Sub(m_Value(s0), m_Value(s1))))
	{
		return false;
	}

	// s0 = a + b
	Value* pa; Value* pb;
	if (!match(s0, m_Add(m_Value(pa), m_Value(pb))))
	{
		return false;
	}

	// s1 = 2 * (a & b) either as mul ..,2 / mul 2,.. or shl ..,1
	Value* aa; Value* ab;
	bool twiceAnd =
			match(s1, m_Mul(m_And(m_Value(aa), m_Value(ab)), m_SpecificInt(2)))
		|| match(s1, m_Mul(m_SpecificInt(2), m_And(m_Value(aa), m_Value(ab))))
		|| match(s1, m_Shl(m_And(m_Value(aa), m_Value(ab)), m_SpecificInt(1)));
	if (!twiceAnd)
	{
		return false;
	}
	if (!((pa == aa && pb == ab) || (pa == ab && pb == aa)))
	{
		return false;
	}

	auto* x = BinaryOperator::CreateXor(pa, pb, "", insn);
	return replaceWith(insn, x);
}

/**
 * MBA XOR, NAND/NOR form:
 *
 * x = ~(a & b) & ~(~a & ~b)
 *   =>
 * x = a ^ b
 */
bool mbaXorNandNor(llvm::Instruction* insn)
{
	Value* l; Value* r;
	if (!match(insn, m_And(m_Value(l), m_Value(r))))
	{
		return false;
	}

	// One side is ~(a & b), the other ~(~a & ~b). Try both orders.
	for (int swap = 0; swap < 2; ++swap)
	{
		Value* lhs = swap ? r : l;
		Value* rhs = swap ? l : r;

		Value* a; Value* b;
		if (!match(lhs, m_Not(m_And(m_Value(a), m_Value(b)))))
		{
			continue;
		}
		Value* na; Value* nb;
		if (!match(rhs, m_And(m_Not(m_Value(na)), m_Not(m_Value(nb)))))
		{
			continue;
		}
		if ((a == na && b == nb) || (a == nb && b == na))
		{
			auto* x = BinaryOperator::CreateXor(a, b, "", insn);
			return replaceWith(insn, x);
		}
	}
	return false;
}

/**
 * MBA ADD, "or plus and" form (either operand order):
 *
 * x = (a | b) + (a & b)
 * x = (a & b) + (a | b)
 *   =>
 * x = a + b
 */
bool mbaAddOrAnd(llvm::Instruction* insn)
{
	Value* p0; Value* p1;
	if (!match(insn, m_Add(m_Value(p0), m_Value(p1))))
	{
		return false;
	}

	for (int swap = 0; swap < 2; ++swap)
	{
		Value* orSide = swap ? p1 : p0;
		Value* andSide = swap ? p0 : p1;

		Value* o0; Value* o1;
		Value* a0; Value* a1;
		if (match(orSide, m_Or(m_Value(o0), m_Value(o1)))
				&& match(andSide, m_And(m_Value(a0), m_Value(a1)))
				&& (((o0 == a0 && o1 == a1) || (o0 == a1 && o1 == a0))))
		{
			auto* x = BinaryOperator::CreateAdd(o0, o1, "", insn);
			return replaceWith(insn, x);
		}
	}
	return false;
}

/**
 * MBA ADD through explicit 32/64-bit casts.
 *
 * zext/sext: cast(or) + cast(and) => cast(a) + cast(b), at root width.
 * trunc:     trunc(or) + trunc(and) => trunc(a + b), at source width.
 *
 * Keeping the original root/source arithmetic width is essential: replacing
 * a widened sum by a widened *wrapped* 32-bit sum would drop its carry.
 */
bool mbaAddOrAndCasts(llvm::Instruction* insn)
{
	Value* p0; Value* p1;
	if (!match(insn, m_Add(m_Value(p0), m_Value(p1))))
	{
		return false;
	}
	for (int swap = 0; swap < 2; ++swap)
	{
		auto* orCast = dyn_cast<CastInst>(swap ? p1 : p0);
		auto* andCast = dyn_cast<CastInst>(swap ? p0 : p1);
		if (orCast == nullptr || andCast == nullptr
				|| orCast->getOpcode() != andCast->getOpcode())
		{
			continue;
		}
		auto* orOp = dyn_cast<BinaryOperator>(orCast->getOperand(0));
		auto* andOp = dyn_cast<BinaryOperator>(andCast->getOperand(0));
		if (orOp == nullptr || andOp == nullptr
				|| orOp->getOpcode() != Instruction::Or
				|| andOp->getOpcode() != Instruction::And)
		{
			continue;
		}
		Value* a = orOp->getOperand(0);
		Value* b = orOp->getOperand(1);
		if (!((andOp->getOperand(0) == a && andOp->getOperand(1) == b)
				|| (andOp->getOperand(0) == b && andOp->getOperand(1) == a)))
		{
			continue;
		}
		auto opcode = orCast->getOpcode();
		bool widen = opcode == Instruction::ZExt || opcode == Instruction::SExt;
		bool narrow = opcode == Instruction::Trunc;
		if (!widen && !narrow)
		{
			continue;
		}
		auto* innerType = dyn_cast<IntegerType>(orOp->getType());
		auto* rootType = dyn_cast<IntegerType>(insn->getType());
		if (innerType == nullptr || rootType == nullptr
				|| andOp->getType() != innerType
				|| (widen && !(innerType->getBitWidth() == 32
						&& rootType->getBitWidth() == 64))
				|| (narrow && !(innerType->getBitWidth() == 64
						&& rootType->getBitWidth() == 32)))
		{
			continue;
		}

		Instruction* result = nullptr;
		if (widen)
		{
			auto* ca = CastInst::Create(opcode, a, rootType, "", insn);
			auto* cb = CastInst::Create(opcode, b, rootType, "", insn);
			result = BinaryOperator::CreateAdd(ca, cb, "", insn);
		}
		else
		{
			auto* sum = BinaryOperator::CreateAdd(a, b, "", insn);
			result = new TruncInst(sum, rootType, "", insn);
		}
		return replaceWith(insn, result);
	}
	return false;
}

/**
 * Double negation:
 *
 * x = ~(~a)
 *   =>
 * x = a
 */
bool notNot(llvm::Instruction* insn)
{
	Value* a;
	if (!match(insn, m_Not(m_Not(m_Value(a)))))
	{
		return false;
	}
	return replaceWith(insn, a);
}

/**
 * Contract De Morgan into a single grouped NOT (more readable):
 *
 * x = ~a | ~b   =>   x = ~(a & b)
 * x = ~a & ~b   =>   x = ~(a | b)
 *
 * This is the readable direction: two NOTs collapse into one.
 */
bool deMorganContract(llvm::Instruction* insn)
{
	Value* a; Value* b;

	if (match(insn, m_Or(m_Not(m_Value(a)), m_Not(m_Value(b)))))
	{
		auto* inner = BinaryOperator::CreateAnd(a, b, "", insn);
		auto* x = BinaryOperator::CreateNot(inner, "", insn);
		return replaceWith(insn, x);
	}
	if (match(insn, m_And(m_Not(m_Value(a)), m_Not(m_Value(b)))))
	{
		auto* inner = BinaryOperator::CreateOr(a, b, "", insn);
		auto* x = BinaryOperator::CreateNot(inner, "", insn);
		return replaceWith(insn, x);
	}
	return false;
}

/**
 * Complement annihilation / saturation:
 *
 * x = a & ~a   =>   x = 0
 * x = a | ~a   =>   x = -1 (all ones)
 */
bool andOrComplement(llvm::Instruction* insn)
{
	Value* a; Value* na;

	if (match(insn, m_And(m_Value(a), m_Not(m_Value(na))))
			|| match(insn, m_And(m_Not(m_Value(na)), m_Value(a))))
	{
		if (a == na)
		{
			return replaceWith(insn, ConstantInt::get(insn->getType(), 0));
		}
	}
	if (match(insn, m_Or(m_Value(a), m_Not(m_Value(na))))
			|| match(insn, m_Or(m_Not(m_Value(na)), m_Value(a))))
	{
		if (a == na)
		{
			return replaceWith(
					insn,
					Constant::getAllOnesValue(insn->getType()));
		}
	}
	return false;
}

/**
 * Absorption with complement:
 *
 * x = (a & b) | (a & ~b)   =>   x = a
 * x = (a | b) & (a | ~b)   =>   x = a
 *
 * b may sit on either side of each inner op, and the two halves may be in
 * either order; the common operand `a` is what we return.
 */
bool absorptionComplement(llvm::Instruction* insn)
{
	// (a & b) | (a & ~b) -> a
	{
		Value* l; Value* r;
		if (match(insn, m_Or(m_And(m_Value(l), m_Value(r)),
				m_Value())))
		{
			Value* x0; Value* x1; Value* y0; Value* y1;
			if (match(insn, m_Or(
					m_And(m_Value(x0), m_Value(x1)),
					m_And(m_Value(y0), m_Value(y1)))))
			{
				// find common value `a` and complementary `b`/`~b`
				Value* cands0[2] = {x0, x1};
				Value* cands1[2] = {y0, y1};
				for (Value* a : cands0)
				{
					Value* bX = (a == x0) ? x1 : x0;
					for (Value* a2 : cands1)
					{
						if (a2 != a) continue;
						Value* bY = (a2 == y0) ? y1 : y0;
						Value* nb;
						if ((match(bY, m_Not(m_Value(nb))) && nb == bX)
							|| (match(bX, m_Not(m_Value(nb))) && nb == bY))
						{
							return replaceWith(insn, a);
						}
					}
				}
			}
		}
	}
	// (a | b) & (a | ~b) -> a
	{
		Value* x0; Value* x1; Value* y0; Value* y1;
		if (match(insn, m_And(
				m_Or(m_Value(x0), m_Value(x1)),
				m_Or(m_Value(y0), m_Value(y1)))))
		{
			Value* cands0[2] = {x0, x1};
			Value* cands1[2] = {y0, y1};
			for (Value* a : cands0)
			{
				Value* bX = (a == x0) ? x1 : x0;
				for (Value* a2 : cands1)
				{
					if (a2 != a) continue;
					Value* bY = (a2 == y0) ? y1 : y0;
					Value* nb;
					if ((match(bY, m_Not(m_Value(nb))) && nb == bX)
						|| (match(bX, m_Not(m_Value(nb))) && nb == bY))
					{
						return replaceWith(insn, a);
					}
				}
			}
		}
	}
	return false;
}

/**
 * Simple absorption:
 *
 * x = a | (a & b)   =>   x = a
 * x = a & (a | b)   =>   x = a
 * (either operand order)
 */
bool absorptionSimple(llvm::Instruction* insn)
{
	Value* a; Value* inner0; Value* inner1;

	// a | (a & b)
	if (match(insn, m_Or(m_Value(a), m_And(m_Value(inner0), m_Value(inner1))))
			|| match(insn, m_Or(m_And(m_Value(inner0), m_Value(inner1)), m_Value(a))))
	{
		if (a == inner0 || a == inner1)
		{
			return replaceWith(insn, a);
		}
	}
	// a & (a | b)
	if (match(insn, m_And(m_Value(a), m_Or(m_Value(inner0), m_Value(inner1))))
			|| match(insn, m_And(m_Or(m_Value(inner0), m_Value(inner1)), m_Value(a))))
	{
		if (a == inner0 || a == inner1)
		{
			return replaceWith(insn, a);
		}
	}
	return false;
}

/**
 * PASS 3 - byte-lane merge.
 *
 * Griffin re-assembles a word from masked lanes of the SAME value:
 *
 * x = (v & maskA) | (v & maskB)   =>   x = v & (maskA | maskB)
 *
 * Only fires when both `and`s are over the same value `v` with constant masks;
 * merging the masks removes a whole `and` + `or` and one hex constant per hit.
 * Safe regardless of whether the masks are disjoint.
 */
bool byteLaneMerge(llvm::Instruction* insn)
{
	Value* v0; Value* v1;
	uint64_t m0; uint64_t m1;

	if (!match(insn, m_Or(
			m_And(m_Value(v0), m_ConstantInt(m0)),
			m_And(m_Value(v1), m_ConstantInt(m1)))))
	{
		return false;
	}
	if (v0 != v1)
	{
		return false;
	}

	auto* merged = BinaryOperator::CreateAnd(
			v0,
			ConstantInt::get(insn->getType(), m0 | m1),
			"",
			insn);
	return replaceWith(insn, merged);
}

/**
 * Order here is important.
 * More specific patterns must go first, more general later.
 */
std::vector<bool (*)(llvm::Instruction*)> optimizations =
{
		&addZero,
		&subZero,
		&truncZext,
		&xorLoadXX,
		&xorXX,
		&xor_i1,
		&and_i1,
		&orAndLoadXX,
		&orAndXX,
		&addSequence,
		// TIER-1 PASS 1 (MBA): specific arith-mixed forms first, then boolean.
		&mbaXorAddSub,
		&mbaXorSubOrAnd,
		&mbaXorNandNor,
		&mbaAddOrAnd,
		&mbaAddOrAndCasts,
		&absorptionComplement,
		&absorptionSimple,
		&andOrComplement,
		&deMorganContract,
		&notNot,
		// TIER-1 PASS 3 (byte lanes): merge masked lanes of the same value.
		&byteLaneMerge,
		&castSequenceWrapper,
		&storeToBitcastPointer,
		&loadFromBitcastPointer,
};

bool optimize(llvm::Instruction* insn)
{
	for (auto& f : optimizations)
	{
		if (f(insn))
		{
			return true;
		}
	}
	return false;
}

} // namespace inst_opt
} // namespace bin2llvmir
} // namespace retdec
