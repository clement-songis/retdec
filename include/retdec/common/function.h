/**
 * @file include/retdec/common/function.h
 * @brief Common function representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_FUNCTION_H
#define RETDEC_COMMON_FUNCTION_H

#include <map>
#include <set>
#include <string>

#include "retdec/common/calling_convention.h"
#include "retdec/common/basic_block.h"
#include "retdec/common/object.h"
#include "retdec/common/storage.h"
#include "retdec/common/type.h"

namespace retdec {
namespace common {

using LineNumber = retdec::common::Address;

/**
 * Represents function.
 *
 * Function's name is its unique ID. Function names in config must be the
 * same as in LLVM IR. Function names in IR must be unique, therefore
 * it is safe to demand unique names in config without loss of generality.
 *
 * Function address is not suitable unique ID. LLVM IR do not know
 * about functions' addresses. Some functions (syscalls) do not have
 * meaningful addresses.
 */
class Function : public retdec::common::AddressRange
{
	public:
		/**
		 * Recognized types of a function that will determine
		 * how the decompiler will treat the specified function.
		 *
		 * When the type is DECOMPILER_DEFINED the decompiler is
		 * allowed to prefer info recieved from some heuristics,
		 * instead of info specified in the config.
		 *
		 * When the type is USER_DEFINED the info about the function
		 * (params, type) specified in a config file will be projected
		 * on the decompiler output and the decompiler should not do
		 * any heuristcs.
		 */
		enum eLinkType
		{
			DECOMPILER_DEFINED = 0,
			USER_DEFINED,
			STATICALLY_LINKED,
			DYNAMICALLY_LINKED,
			SYSCALL,
			IDIOM
		};

	public:
		Function(const std::string& name = std::string());
		Function(
			retdec::common::Address start,
			retdec::common::Address end,
			const std::string& name = std::string());

		/// @name Function query methods.
		/// @{
		bool isDecompilerDefined() const;
		bool isUserDefined() const;
		bool isStaticallyLinked() const;
		bool isDynamicallyLinked() const;
		bool isSyscall() const;
		bool isIdiom() const;
		bool isFromDebug() const;
		bool isWrapper() const;
		bool isConstructor() const;
		bool isDestructor() const;
		bool isVirtual() const;
		bool isExported() const;
		bool isVariadic() const;
		bool isThumb() const;
		/// @}

		/// @name Function set methods.
		/// @{
		void setName(const std::string& n);
		void setRealName(const std::string& n);
		void setDemangledName(const std::string& n);
		void setComment(const std::string& c);
		void addComment(const std::string& c);
		void setDeclarationString(const std::string& s);
		void setSourceFileName(const std::string& n);
		void setWrappedFunctionName(const std::string& n);
		void setStartLine(const retdec::common::Address& l);
		void setEndLine(const retdec::common::Address& l);
		void setIsDecompilerDefined();
		void setIsUserDefined();
		void setIsStaticallyLinked() const;
		void setIsDynamicallyLinked() const;
		void setIsSyscall();
		void setIsIdiom();
		void setIsFromDebug(bool d);
		void setIsConstructor(bool f);
		void setIsDestructor(bool f);
		void setIsVirtual(bool f);
		void setIsExported(bool f);
		void setIsVariadic(bool f);
		void setIsThumb(bool f);
		void setLinkType(eLinkType lt);
		/// @}

		/// @name Function get methods.
		/// @{
		const std::string& getId() const;
		const std::string& getName() const;
		const std::string& getRealName() const;
		std::string getDemangledName() const;
		std::string getComment() const;
		std::string getDeclarationString() const;
		std::string getSourceFileName() const;
		std::string getWrappedFunctionName() const;
		LineNumber getStartLine() const;
		LineNumber getEndLine() const;
		eLinkType getLinkType() const;
		/// @}

		bool operator<(const Function& o) const;
		bool operator==(const Function& o) const;
		bool operator!=(const Function& o) const;

	public:
		common::CallingConvention callingConvention;
		common::Storage returnStorage;
		common::Storage frameBaseStorage;
		common::Type returnType;
		common::ObjectSequentialContainer parameters;
		common::ObjectSetContainer locals;
		std::set<std::string> usedCryptoConstants;
		std::set<common::BasicBlock> basicBlocks;
		/// Addresses of instructions which reference (use) this  function.
		std::set<common::Address> codeReferences;

	private:
		std::string _name; ///< This is objects unique ID.
		std::string _realName;
		std::string _demangledName;
		std::string _comment;
		std::string _declarationString;
		std::string _sourceFileName;
		std::string _wrapperdFunctionName;
		mutable eLinkType _linkType = DECOMPILER_DEFINED;
		LineNumber _startLine;
		LineNumber _endLine;
		bool _fromDebug = false;
		bool _constructor = false;
		bool _destructor = false;
		bool _virtualFunction = false;
		bool _exported = false;
		bool _variadic = false;
		bool _thumb = false;
};

struct FunctionNameCompare
{
	using is_transparent = void;

	bool operator()(const Function& f1, const Function& f2) const
	{
		return f1 < f2;
	}
	bool operator()(const std::string& id, Function const& f) const
	{
		return id < f.getName();
	}
	bool operator()(const Function& f, const std::string& id) const
	{
		return f.getName() < id;
	}
};

struct FunctionAddressCompare
{
	using is_transparent = void;

	bool operator()(const Function& f1, const Function& f2) const
	{
		return f1.getStart() < f2.getStart();
	}
	bool operator()(const retdec::common::Address& id, Function const& f) const
	{
		return id < f.getStart();
	}
	bool operator()(const Function& f, const retdec::common::Address& id) const
	{
		return f.getStart() < id;
	}
};

/**
 * An associative container with functions' names as the key.
 * See Function class for details.
 */
class FunctionContainer : public std::set<Function, FunctionNameCompare>
{
	public:
		using Base = std::set<Function, FunctionNameCompare>;

		bool hasFunction(const std::string& name);
		const Function* getFunctionByName(const std::string& name) const;
		const Function* getFunctionByStartAddress(
				const retdec::common::Address& addr) const;
		const Function* getFunctionByRealName(const std::string& name) const;

		// Maintien de l'index adresse->fonction (voir plus bas).
		// - insert : mise a jour INCREMENTALE si l'index est deja bati. Ne PAS tout
		//   invalider, sinon un insert suivi d'un lookup dans la meme boucle
		//   (ex. Decoder::initConfigFunctions) reconstruit l'index a chaque tour =
		//   O(n^2) reintroduit. std::set::insert n'invalide pas les pointeurs vers
		//   les elements existants, donc les entrees deja en cache restent valides.
		// - erase/clear : invalidation totale (rare ici ; un erase pendouillerait
		//   des pointeurs en cache).
		std::pair<iterator,bool> insert(const value_type& v)
		{
			auto p = Base::insert(v);
			if (!_addr2fncDirty && p.second)
				_addr2fnc.emplace(p.first->getStart(), &(*p.first));
			return p;
		}
		std::pair<iterator,bool> insert(value_type&& v)
		{
			auto p = Base::insert(std::move(v));
			if (!_addr2fncDirty && p.second)
				_addr2fnc.emplace(p.first->getStart(), &(*p.first));
			return p;
		}
		// Surcharges avec hint (utilisees par la (de)serialisation) : mise a jour
		// incrementale en verifiant que l'element n'etait pas deja present.
		iterator insert(const_iterator hint, const value_type& v)
		{
			auto before = Base::size();
			auto it = Base::insert(hint, v);
			if (!_addr2fncDirty && Base::size() != before)
				_addr2fnc.emplace(it->getStart(), &(*it));
			return it;
		}
		iterator insert(const_iterator hint, value_type&& v)
		{
			auto before = Base::size();
			auto it = Base::insert(hint, std::move(v));
			if (!_addr2fncDirty && Base::size() != before)
				_addr2fnc.emplace(it->getStart(), &(*it));
			return it;
		}
		template <typename InputIt>
		void insert(InputIt first, InputIt last)
		{
			_addr2fncDirty = true;
			Base::insert(first, last);
		}
		template <typename... Args>
		auto erase(Args&&... args)
		{
			_addr2fncDirty = true;
			return Base::erase(std::forward<Args>(args)...);
		}
		void clear() { _addr2fncDirty = true; Base::clear(); }

	private:
		// Index paresseux adresse->fonction pour getFunctionByStartAddress.
		// Le conteneur est trie par NOM (FunctionNameCompare), donc une recherche
		// par adresse etait un scan lineaire O(n) ; appelee par constante-adresse
		// dans la passe retdec-constants, cela donnait un O(n^2) qui rendait la
		// decompilation de grandes plages .grfn1 intractable. On maintient un cache
		// adresse->Function*, bati paresseusement puis tenu a jour incrementalement.
		mutable std::map<retdec::common::Address, const Function*> _addr2fnc;
		mutable bool _addr2fncDirty = true;
};

// TODO:
// Maybe we could use common::RangeContainer for this.
// It contains this functionality, but also some other mechanisms with
// potentially unwanted side effects.
// Also, because it does not take range as template argument, it is not ready
// to be used with common::Function.
class FunctionSet : public std::set<
		retdec::common::Function,
		retdec::common::FunctionAddressCompare>
{
	public:
		const retdec::common::Function* getRange(
				const retdec::common::Address& a) const;
};

} // namespace common
} // namespace retdec

#endif
