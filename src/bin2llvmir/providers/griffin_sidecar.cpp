/**
* @file src/bin2llvmir/providers/griffin_sidecar.cpp
* @brief Validated Griffin dynamic control-flow evidence.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <regex>
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

std::optional<uint64_t> littleEndianUint64(const std::string& text)
{
	if (text.size() != 16
			|| !std::all_of(text.begin(), text.end(), [](unsigned char c) {
				return std::isxdigit(c) != 0;
			}))
	{
		return std::nullopt;
	}
	uint64_t value = 0;
	for (unsigned byte = 0; byte < 8; ++byte)
	{
		auto octet = std::stoul(text.substr(byte * 2, 2), nullptr, 16);
		value |= static_cast<uint64_t>(octet) << (byte * 8);
	}
	return value;
}

int64_t jsonDisplacement(const rapidjson::Value& value)
{
	if (value.IsInt64())
	{
		return value.GetInt64();
	}
	if (value.IsString())
	{
		std::size_t used = 0;
		std::string text = value.GetString();
		auto result = std::stoll(text, &used, 0);
		if (used == text.size())
		{
			return result;
		}
	}
	throw std::runtime_error("invalid Griffin stack displacement");
}

GriffinSidecar::StackSlotRole stackSlotRole(const rapidjson::Value& observation)
{
	auto it = observation.FindMember("stackSlot");
	if (it == observation.MemberEnd() || !it->value.IsObject())
	{
		return GriffinSidecar::StackSlotRole::Unknown;
	}
	auto role = it->value.FindMember("role");
	if (role == it->value.MemberEnd() || !role->value.IsString())
	{
		return GriffinSidecar::StackSlotRole::Unknown;
	}
	std::string value = role->value.GetString();
	if (value == "abi-frame")
	{
		return GriffinSidecar::StackSlotRole::AbiFrame;
	}
	if (value == "vm-register")
	{
		return GriffinSidecar::StackSlotRole::VmRegister;
	}
	if (value == "vm-spill")
	{
		return GriffinSidecar::StackSlotRole::VmSpill;
	}
	return GriffinSidecar::StackSlotRole::Unknown;
}

std::optional<GriffinSidecar::StackSlot> observedStackSlot(
		const rapidjson::Value& observation,
		const std::string& imageSha256)
{
	try
	{
		if (!stringMemberIs(observation, "classification", "dynamic-verified"))
		{
			return std::nullopt;
		}
		auto source = jsonAddress(requiredMember(observation, "sourceRva"), "sourceRva");
		auto target = jsonAddress(requiredMember(observation, "targetRva"), "targetRva");
		if (!v2ObservationMatches(
				source, target, "dynamic-verified", imageSha256, observation))
		{
			return std::nullopt;
		}

		auto& textValue = requiredMember(observation, "text");
		if (!textValue.IsString())
		{
			return std::nullopt;
		}
		// Deliberately exclude scaled/indexed forms: their dynamic address
		// cannot be attributed to a constant RSP slot from this observation.
		static const std::regex rspOperand(
				"^(call|jmp) qword ptr \\[rsp(?: ([+-]) (0x[0-9a-fA-F]+|[0-9]+))?\\]$");
		std::smatch match;
		std::string text = textValue.GetString();
		if (!std::regex_match(text, match, rspOperand))
		{
			return std::nullopt;
		}
		uint64_t displacement = 0;
		if (match[3].matched)
		{
			std::size_t used = 0;
			std::string textDisplacement = match[3].str();
			displacement = std::stoull(textDisplacement, &used, 0);
			if (used != textDisplacement.size())
			{
				return std::nullopt;
			}
		}
		if (displacement > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
		{
			return std::nullopt;
		}
		auto rsp = jsonAddress(requiredMember(observation, "rsp"), "rsp");
		auto& context = requiredMember(observation, "context");
		auto& registers = requiredMember(context, "registers");
		if (jsonAddress(requiredMember(registers, "rsp"), "context.registers.rsp") != rsp)
		{
			return std::nullopt;
		}
		bool subtract = match[2].matched && match[2].str() == "-";
		if ((subtract && displacement > rsp)
				|| (!subtract && displacement > UINT64_MAX - rsp))
		{
			return std::nullopt;
		}
		uint64_t address = subtract ? rsp - displacement : rsp + displacement;
		auto targetVa = jsonAddress(requiredMember(observation, "targetVa"), "targetVa");

		bool matchingMemory = false;
		auto& memory = requiredMember(context, "memory");
		if (!memory.IsArray())
		{
			return std::nullopt;
		}
		for (const auto& item : memory.GetArray())
		{
			if (!item.IsObject()
					|| jsonAddress(requiredMember(item, "address"), "memory.address") != address
					|| jsonAddress(requiredMember(item, "size"), "memory.size") != 8)
			{
				continue;
			}
			auto& data = requiredMember(item, "data");
			if (!data.IsString())
			{
				continue;
			}
			auto value = littleEndianUint64(data.GetString());
			matchingMemory = value && *value == targetVa;
			if (matchingMemory)
			{
				break;
			}
		}
		if (!matchingMemory)
		{
			return std::nullopt;
		}

		GriffinSidecar::StackSlot slot;
		slot.displacement = subtract
				? -static_cast<int64_t>(displacement)
				: static_cast<int64_t>(displacement);
		slot.address = address;
		slot.size = 8;
		slot.role = stackSlotRole(observation);
		auto annotation = observation.FindMember("stackSlot");
		if (annotation != observation.MemberEnd() && annotation->value.IsObject())
		{
			auto annotatedDisplacement = annotation->value.FindMember("displacement");
			if (annotatedDisplacement != annotation->value.MemberEnd()
					&& jsonDisplacement(annotatedDisplacement->value) != slot.displacement)
			{
				return std::nullopt;
			}
		}
		return slot;
	}
	catch (const std::exception&)
	{
		return std::nullopt;
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
	for (const char* name : {"staticImageBase", "preferredTraceBase", "runtimeImageBase"})
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
			auto slot = observedStackSlot(observation, result._imageSha256);
			if (slot)
			{
				auto source = jsonAddress(
						requiredMember(observation, "sourceRva"), "sourceRva");
				auto inserted = result._stackSlots.emplace(source, *slot);
				if (!inserted.second
						&& (inserted.first->second.displacement != slot->displacement
								|| inserted.first->second.role != slot->role))
				{
					// Disagreement about a role is itself unknown. Never pick
					// the most convenient interpretation.
					inserted.first->second.role = GriffinSidecar::StackSlotRole::Unknown;
				}
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
		bool provedTargetSet = false;
		bool dynamicVerified = false;
		uint64_t target = 0;
		ControlTargetSet targetSet;
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

			// A CFF target set is a different proof from a single observed
			// successor. Require explicit exhaustiveness and support every
			// target with a clean replay. Partial observed sets stay rejected.
			if (!proved && eligible && kind == "jmp"
					&& classification == "dynamic-verified"
					&& boolMemberIs(site, "targetSetComplete", true)
					&& targetsIt != site.MemberEnd()
					&& targetsIt->value.IsArray()
					&& targetsIt->value.Size() > 1
					&& observationIdsIt != site.MemberEnd()
					&& observationIdsIt->value.IsArray()
					&& observationIdsIt->value.Size() != 0)
			{
				std::map<uint64_t, uint64_t> caseByTarget;
				std::set<uint64_t> caseValues;
				bool casesValid = true;
				auto casesIt = site.FindMember("targetCases");
				bool hasCases = casesIt != site.MemberEnd();
				casesValid = hasCases || !site.HasMember("stateOperand");
				if (hasCases)
				{
					casesValid = casesValid && stringMemberIs(
									site, "stateOperand", "pseudo-arg")
							&& casesIt->value.IsArray()
							&& casesIt->value.Size() == targetsIt->value.Size();
					if (casesValid)
					{
						for (const auto& caseValue : casesIt->value.GetArray())
						{
							if (!caseValue.IsObject())
							{
								casesValid = false;
								break;
							}
							auto caseTarget = jsonAddress(
									requiredMember(caseValue, "targetRva"), "targetRva");
							auto state = jsonAddress(
									requiredMember(caseValue, "stateValue"), "stateValue");
							if (!caseByTarget.emplace(caseTarget, state).second
									|| !caseValues.insert(state).second)
							{
								casesValid = false;
								break;
							}
						}
					}
				}

				std::set<uint64_t> uniqueTargets;
				proved = casesValid;
				for (const auto& targetValue : targetsIt->value.GetArray())
				{
					auto candidate = jsonAddress(targetValue, "targets[]");
					if (candidate == 0 || candidate >= result._imageSize
							|| !uniqueTargets.insert(candidate).second
							|| (hasCases && caseByTarget.count(candidate) == 0))
					{
						proved = false;
						break;
					}
					std::optional<uint64_t> state;
					if (hasCases)
					{
						state = caseByTarget.at(candidate);
					}
					bool supportingObservation = false;
					for (const auto& id : observationIdsIt->value.GetArray())
					{
						if (!id.IsString())
						{
							continue;
						}
						auto observation = observations.find(id.GetString());
						if (observation == observations.end()
								|| !v2ObservationMatches(
										source, candidate, classification,
										result._imageSha256, *observation->second))
						{
							continue;
						}
						if (state)
						{
							auto stateIt = observation->second->FindMember("stateValue");
							if (stateIt == observation->second->MemberEnd()
									|| jsonAddress(stateIt->value, "stateValue") != *state)
							{
								continue;
							}
						}
						supportingObservation = true;
						break;
					}
					if (!supportingObservation)
					{
						proved = false;
						break;
					}
					targetSet.targets.push_back(ControlTarget{
							candidate, kind, classification, state});
				}
				proved = proved
						&& uniqueTargets.size() == targetsIt->value.Size()
						&& (!hasCases || caseByTarget.size() == uniqueTargets.size());
				if (proved)
				{
					targetSet.stateFromPseudoArgument = hasCases;
					provedTargetSet = true;
				}
				else
				{
					targetSet.targets.clear();
				}
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

		if (provedTargetSet)
		{
			auto inserted = result._controlTargetSets.emplace(source, targetSet);
			if (!inserted.second)
			{
				throw std::runtime_error("conflicting Griffin CFF target-set evidence");
			}
		}
		else if (proved)
		{
			ControlTarget controlTarget{target, kind,
					dynamicVerified ? "dynamic-verified" : "static", std::nullopt};
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
		if (result._evidenceV2 && !proved)
		{
			result._rejectedControlTargets[source] = kind;
		}
	}
	return result;
}

GriffinSidecar::ControlStatus GriffinSidecar::getControlStatus(
		Address site,
		const std::string& kind) const
{
	if (site.isUndefined())
	{
		return ControlStatus::Unknown;
	}
	for (uint64_t base : _bases)
	{
		uint64_t value = site.getValue();
		if (value < base || value - base >= _imageSize)
		{
			continue;
		}
		uint64_t source = value - base;
		if (_controlTargets.count(source)
				&& _controlTargets.at(source).kind == kind)
		{
			return ControlStatus::Proven;
		}
		if (_controlTargetSets.count(source))
		{
			const auto& targets = _controlTargetSets.at(source).targets;
			if (!targets.empty() && targets.front().kind == kind)
			{
				return ControlStatus::Proven;
			}
		}
		if (_rejectedControlTargets.count(source)
				&& _rejectedControlTargets.at(source) == kind)
		{
			return ControlStatus::Rejected;
		}
		return ControlStatus::Unknown;
	}
	return ControlStatus::Unknown;
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

std::optional<GriffinSidecar::ControlFlowTargetSet>
GriffinSidecar::getControlTargetSet(
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
		auto it = _controlTargetSets.find(value - base);
		if (it == _controlTargetSets.end() || it->second.targets.empty()
				|| it->second.targets.front().kind != kind)
		{
			return std::nullopt;
		}
		ControlFlowTargetSet result;
		result.stateFromPseudoArgument = it->second.stateFromPseudoArgument;
		for (const auto& target : it->second.targets)
		{
			result.targets.push_back(ControlFlowTarget{
					Address(base + target.targetRva), target.stateValue});
		}
		return result;
	}
	return std::nullopt;
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

std::size_t GriffinSidecar::getControlTargetSetCount() const
{
	return _controlTargetSets.size();
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

std::optional<GriffinSidecar::StackSlot> GriffinSidecar::getStackSlot(
		Address site) const
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
		auto it = _stackSlots.find(value - base);
		if (it == _stackSlots.end())
		{
			return std::nullopt;
		}
		auto slot = it->second;
		return slot;
	}
	return std::nullopt;
}

std::size_t GriffinSidecar::getStackSlotCount() const
{
	return _stackSlots.size();
}

std::size_t GriffinSidecar::getAbiFrameStackSlotCount() const
{
	return std::count_if(_stackSlots.begin(), _stackSlots.end(), [](const auto& item) {
		return item.second.role == StackSlotRole::AbiFrame;
	});
}

} // namespace bin2llvmir
} // namespace retdec
