/**
* @file src/bin2llvmir/providers/griffin_sidecar.cpp
* @brief Validated Griffin dynamic control-flow evidence.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <algorithm>
#include <cctype>
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

std::string lower(std::string text)
{
	std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return text;
}

bool isSha256(const std::string& text)
{
	return text.size() == 64
			&& std::all_of(text.begin(), text.end(), [](unsigned char c) {
				return std::isxdigit(c) != 0;
			});
}

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

bool stringMemberIs(
		const rapidjson::Value& object,
		const char* name,
		const std::string& expected)
{
	auto it = object.FindMember(name);
	return it != object.MemberEnd()
			&& it->value.IsString()
			&& expected == it->value.GetString();
}

bool boolMemberIs(
		const rapidjson::Value& object,
		const char* name,
		bool expected)
{
	auto it = object.FindMember(name);
	return it != object.MemberEnd()
			&& it->value.IsBool()
			&& it->value.GetBool() == expected;
}

bool v2ObservationMatches(
		uint64_t source,
		uint64_t target,
		const std::string& classification,
		const std::string& imageSha256,
		const rapidjson::Value& observation)
{
	try
	{
		if (jsonAddress(requiredMember(observation, "sourceRva"), "sourceRva") != source
				|| jsonAddress(requiredMember(observation, "targetRva"), "targetRva") != target
				|| !stringMemberIs(observation, "classification", classification)
				|| !stringMemberIs(observation, "imageSha256", imageSha256))
		{
			return false;
		}
		if (classification == "static")
		{
			return jsonAddress(
					requiredMember(observation, "staticTargetRva"),
					"staticTargetRva") == target;
		}
		if (classification != "dynamic-verified")
		{
			return false;
		}

		auto& context = requiredMember(observation, "context");
		auto& replay = requiredMember(observation, "replay");
		auto& taint = requiredMember(observation, "scratch-taint");
		return boolMemberIs(context, "complete", true)
				&& stringMemberIs(replay, "status", "match")
				&& jsonAddress(
						requiredMember(replay, "actualTargetRva"),
						"actualTargetRva") == target
				&& boolMemberIs(taint, "tainted", false)
				&& boolMemberIs(taint, "unknown", false);
	}
	catch (const std::exception&)
	{
		return false;
	}
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
	if (!format.IsString())
	{
		throw std::runtime_error("unsupported Griffin sidecar format");
	}
	std::string formatName = format.GetString();
	if (formatName == "retdec-griffin-dynamic-sidecar-v1")
	{
		result._evidenceV2 = false;
	}
	else if (formatName == "retdec-griffin-evidence-v2")
	{
		result._evidenceV2 = true;
	}
	else
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

	std::map<std::string, const rapidjson::Value*> observations;
	if (result._evidenceV2)
	{
		auto& image = requiredMember(root, "image");
		if (!image.IsObject())
		{
			throw std::runtime_error("Griffin v2 image is not an object");
		}
		auto& hash = requiredMember(image, "sha256");
		if (!hash.IsString() || !isSha256(hash.GetString()))
		{
			throw std::runtime_error("invalid Griffin v2 image.sha256");
		}
		result._imageSha256 = lower(hash.GetString());
		if (!stringMemberIs(image, "layout", "rva"))
		{
			throw std::runtime_error("Griffin v2 image layout is not RVA");
		}

		auto& items = requiredMember(root, "observations");
		if (!items.IsArray())
		{
			throw std::runtime_error("Griffin v2 observations is not an array");
		}
		for (const auto& observation : items.GetArray())
		{
			if (!observation.IsObject())
			{
				throw std::runtime_error("Griffin v2 observation is not an object");
			}
			auto& id = requiredMember(observation, "observationId");
			if (id.IsString())
			{
				observations[id.GetString()] = &observation;
			}
		}
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
		auto& kindValue = requiredMember(site, "kind");
		if (!kindValue.IsString())
		{
			continue;
		}
		std::string kind = kindValue.GetString();
		if (!result._evidenceV2 && kind != "ret")
		{
			continue;
		}
		uint64_t source = jsonAddress(requiredMember(site, "siteRva"), "siteRva");
		if (source >= result._imageSize)
		{
			throw std::runtime_error("Griffin control-flow site is outside the image");
		}

		bool proved = false;
		bool dynamicVerified = false;
		uint64_t target = 0;
		if (!result._evidenceV2)
		{
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
		}
		else
		{
			auto eligibleIt = site.FindMember("providerEligible");
			auto classIt = site.FindMember("classification");
			std::string classification = classIt != site.MemberEnd()
					&& classIt->value.IsString()
					? classIt->value.GetString()
					: "";
			bool eligible = eligibleIt != site.MemberEnd()
					&& eligibleIt->value.IsBool()
					&& eligibleIt->value.GetBool()
					&& (classification == "static" || classification == "dynamic-verified");
			auto targetIt = site.FindMember("targetRva");
			auto targetsIt = site.FindMember("targets");
			auto observationIdsIt = site.FindMember("observationIds");
			if (eligible
					&& targetIt != site.MemberEnd() && !targetIt->value.IsNull()
					&& targetsIt != site.MemberEnd()
					&& targetsIt->value.IsArray()
					&& targetsIt->value.Size() == 1
					&& observationIdsIt != site.MemberEnd()
					&& observationIdsIt->value.IsArray()
					&& observationIdsIt->value.Size() != 0)
			{
				target = jsonAddress(targetIt->value, "targetRva");
				uint64_t uniqueTarget = jsonAddress(
						targetsIt->value[0], "targets[0]");
				proved = target != 0 && target < result._imageSize
						&& uniqueTarget == target;
				if (proved)
				{
					bool supportingObservation = false;
					for (const auto& id : observationIdsIt->value.GetArray())
					{
						if (!id.IsString())
						{
							continue;
						}
						auto observation = observations.find(id.GetString());
						if (observation != observations.end()
								&& v2ObservationMatches(
										source, target, classification,
										result._imageSha256,
										*observation->second))
						{
							supportingObservation = true;
							break;
						}
					}
					proved = supportingObservation;
				}
				dynamicVerified = proved && classification == "dynamic-verified";
			}

			// The ret hook remains restricted to stack trampolines, even when
			// v2 marks an ordinary return edge as provider-eligible.
			if (proved && kind == "ret")
			{
				auto trampolineIt = site.FindMember("stackTrampolineEvidence");
				if (trampolineIt == site.MemberEnd()
						|| !trampolineIt->value.IsObject())
				{
					proved = false;
				}
				else
				{
					auto textIt = trampolineIt->value.FindMember("text");
					proved = boolMemberIs(
									trampolineIt->value, "targetStillUnresolved", false)
							&& textIt != trampolineIt->value.MemberEnd()
							&& textIt->value.IsString()
							&& std::string(textIt->value.GetString()).rfind("push", 0) == 0;
				}
			}
		}

		if (proved)
		{
			ControlTarget controlTarget{target, kind,
					dynamicVerified ? "dynamic-verified" : "static"};
			auto inserted = result._controlTargets.emplace(source, controlTarget);
			if (!inserted.second
					&& (inserted.first->second.targetRva != target
							|| inserted.first->second.kind != kind))
			{
				throw std::runtime_error("conflicting Griffin control-flow evidence");
			}
			if (kind == "ret")
			{
				auto retInserted = result._retTargets.emplace(source, target);
				if (!retInserted.second && retInserted.first->second != target)
				{
					throw std::runtime_error("conflicting Griffin ret-trampoline evidence");
				}
			}
			if (dynamicVerified)
			{
				result._dynamicVerifiedTargetCount += 1;
			}
		}
		else if (kind == "ret")
		{
			result._unresolvedRets.insert(source);
		}
	}
	return result;
}

std::optional<Address> GriffinSidecar::getTarget(
		Address site,
		const std::string& kind) const
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
		auto it = _controlTargets.find(source);
		if (it != _controlTargets.end() && it->second.kind == kind)
		{
			return Address(base + it->second.targetRva);
		}
		return std::nullopt;
	}
	return std::nullopt;
}

std::optional<Address> GriffinSidecar::getControlTarget(
		Address site,
		const std::string& kind) const
{
	return getTarget(site, kind);
}

std::optional<Address> GriffinSidecar::getRetTrampolineTarget(Address site) const
{
	return getTarget(site, "ret");
}

bool GriffinSidecar::checkImageSha256(const std::string& actualSha256) const
{
	// v1 had no image hash field and remains supported for backwards
	// compatibility. v2 must match the FileFormat opened by RetDec.
	return !_evidenceV2
			|| (!actualSha256.empty() && lower(actualSha256) == _imageSha256);
}

bool GriffinSidecar::isEvidenceV2() const
{
	return _evidenceV2;
}

std::size_t GriffinSidecar::getControlTargetCount() const
{
	return _controlTargets.size();
}

std::size_t GriffinSidecar::getDynamicVerifiedTargetCount() const
{
	return _dynamicVerifiedTargetCount;
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
