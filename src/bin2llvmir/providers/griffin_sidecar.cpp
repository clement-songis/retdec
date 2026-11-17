/**
* @file src/bin2llvmir/providers/griffin_sidecar.cpp
* @brief Validated Griffin dynamic control-flow evidence.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <fstream>
#include <iterator>
#include <stdexcept>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include "retdec/bin2llvmir/providers/griffin_sidecar.h"

using retdec::common::Address;

namespace retdec {
namespace bin2llvmir {
namespace {

uint64_t jsonAddress(const rapidjson::Value& value, const char* field)
{
	try
	{
		if (value.IsString())
		{
			std::size_t used = 0;
			std::string text(value.GetString());
			auto result = std::stoull(text, &used, 0);
			if (used == text.size())
			{
				return result;
			}
		}
		else if (value.IsUint64())
		{
			return value.GetUint64();
		}
	}
	catch (const std::exception&)
	{
	}
	throw std::runtime_error(std::string("invalid Griffin address field: ") + field);
}

const rapidjson::Value& requiredMember(
		const rapidjson::Value& object,
		const char* name)
{
	auto it = object.FindMember(name);
	if (it == object.MemberEnd())
	{
		throw std::runtime_error(std::string("missing Griffin sidecar member: ") + name);
	}
	return it->value;
}

} // namespace

GriffinSidecar GriffinSidecar::fromFile(const std::string& path)
{
	std::ifstream input(path);
	if (!input)
	{
		throw std::runtime_error("can not open Griffin sidecar: " + path);
	}
	std::string json{
			std::istreambuf_iterator<char>(input),
			std::istreambuf_iterator<char>()};
	rapidjson::Document root;
	rapidjson::ParseResult parsed = root.Parse(json);
	if (!parsed)
	{
		throw std::runtime_error(
				"invalid Griffin sidecar JSON: "
				+ std::string(rapidjson::GetParseError_En(parsed.Code())));
	}
	if (!root.IsObject())
	{
		throw std::runtime_error("Griffin sidecar root is not an object");
	}

	GriffinSidecar result;
	auto& format = requiredMember(root, "format");
	if (!format.IsString()
			|| std::string(format.GetString()) != "retdec-griffin-dynamic-sidecar-v1")
	{
		throw std::runtime_error("unsupported Griffin sidecar format");
	}
	auto& model = requiredMember(root, "addressModel");
	if (!model.IsObject())
	{
		throw std::runtime_error("Griffin addressModel is not an object");
	}
	result._imageSize = jsonAddress(requiredMember(model, "imageSize"), "imageSize");
	if (result._imageSize == 0)
	{
		throw std::runtime_error("empty Griffin imageSize");
	}
	for (const char* name : {"preferredTraceBase", "runtimeImageBase"})
	{
		auto it = model.FindMember(name);
		if (it != model.MemberEnd())
		{
			result._bases.push_back(jsonAddress(it->value, name));
		}
	}
	if (result._bases.empty())
	{
		throw std::runtime_error("Griffin sidecar has no image base");
	}

	auto& sites = requiredMember(root, "controlFlowSites");
	if (!sites.IsArray())
	{
		throw std::runtime_error("Griffin controlFlowSites is not an array");
	}
	for (const auto& site : sites.GetArray())
	{
		if (!site.IsObject())
		{
			throw std::runtime_error("Griffin control-flow site is not an object");
		}
		auto& kind = requiredMember(site, "kind");
		if (!kind.IsString() || std::string(kind.GetString()) != "ret")
		{
			continue;
		}
		uint64_t source = jsonAddress(requiredMember(site, "siteRva"), "siteRva");
		if (source >= result._imageSize)
		{
			throw std::runtime_error("Griffin ret site is outside the image");
		}

		bool proved = false;
		uint64_t target = 0;
		auto targetIt = site.FindMember("targetRva");
		auto resolutionIt = site.FindMember("resolution");
		auto trampolineIt = site.FindMember("stackTrampolineEvidence");
		auto proofIt = site.FindMember("proof");
		auto successorIt = site.FindMember("successorProof");
		if (targetIt != site.MemberEnd() && !targetIt->value.IsNull()
				&& resolutionIt != site.MemberEnd()
				&& resolutionIt->value.IsString()
				&& std::string(resolutionIt->value.GetString()) == "observed-successor-node"
				&& trampolineIt != site.MemberEnd()
				&& trampolineIt->value.IsObject()
				&& proofIt != site.MemberEnd()
				&& proofIt->value.IsArray() && proofIt->value.Size() != 0
				&& successorIt != site.MemberEnd()
				&& successorIt->value.IsObject()
				&& successorIt->value.HasMember("node"))
		{
			auto unresolvedIt = trampolineIt->value.FindMember("targetStillUnresolved");
			auto textIt = trampolineIt->value.FindMember("text");
			proved = unresolvedIt != trampolineIt->value.MemberEnd()
					&& unresolvedIt->value.IsBool()
					&& !unresolvedIt->value.GetBool()
					&& textIt != trampolineIt->value.MemberEnd()
					&& textIt->value.IsString()
					&& std::string(textIt->value.GetString()).rfind("push", 0) == 0;
			if (proved)
			{
				target = jsonAddress(targetIt->value, "targetRva");
				proved = target < result._imageSize;
			}
		}

		if (proved)
		{
			auto inserted = result._retTargets.emplace(source, target);
			if (!inserted.second && inserted.first->second != target)
			{
				throw std::runtime_error("conflicting Griffin ret-trampoline evidence");
			}
		}
		else
		{
			result._unresolvedRets.insert(source);
		}
	}
	return result;
}

std::optional<Address> GriffinSidecar::getRetTrampolineTarget(Address site) const
{
	if (site.isUndefined())
	{
		return std::nullopt;
	}
	for (uint64_t base : _bases)
	{
		uint64_t value = site.getValue();
		if (value < base || value - base >= _imageSize)
		{
			continue;
		}
		uint64_t source = value - base;
		auto it = _retTargets.find(source);
		if (it != _retTargets.end())
		{
			return Address(base + it->second);
		}
		return std::nullopt;
	}
	return std::nullopt;
}

std::size_t GriffinSidecar::getRetTargetCount() const
{
	return _retTargets.size();
}

std::size_t GriffinSidecar::getUnresolvedRetCount() const
{
	return _unresolvedRets.size();
}

} // namespace bin2llvmir
} // namespace retdec
