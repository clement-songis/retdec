/**
* @file src/bin2llvmir/providers/griffin_overlay.cpp
* @brief Opt-in application of validated dynamic bytes for Griffin analysis.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include "retdec/bin2llvmir/providers/griffin_overlay.h"

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
	throw std::runtime_error(std::string("invalid Griffin overlay address: ") + field);
}

const rapidjson::Value& requiredMember(
		const rapidjson::Value& object,
		const char* name)
{
	auto it = object.FindMember(name);
	if (it == object.MemberEnd())
	{
		throw std::runtime_error(std::string("missing Griffin overlay member: ") + name);
	}
	return it->value;
}

std::uint8_t hexNibble(char c)
{
	if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
	if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
	if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
	throw std::runtime_error("invalid Griffin overlay hex digit");
}

std::vector<std::uint8_t> parseHex(const std::string& text)
{
	if (text.size() % 2 != 0)
	{
		throw std::runtime_error("odd Griffin overlay hex length");
	}
	std::vector<std::uint8_t> bytes;
	bytes.reserve(text.size() / 2);
	for (std::size_t i = 0; i < text.size(); i += 2)
	{
		bytes.push_back(static_cast<std::uint8_t>(
				(hexNibble(text[i]) << 4) | hexNibble(text[i + 1])));
	}
	return bytes;
}

} // namespace

GriffinOverlay GriffinOverlay::fromFile(const std::string& path)
{
	std::ifstream input(path);
	if (!input)
	{
		throw std::runtime_error("can not open Griffin overlay: " + path);
	}
	std::string json{
			std::istreambuf_iterator<char>(input),
			std::istreambuf_iterator<char>()};
	rapidjson::Document root;
	rapidjson::ParseResult parsed = root.Parse(json);
	if (!parsed)
	{
		throw std::runtime_error(
				"invalid Griffin overlay JSON: "
				+ std::string(rapidjson::GetParseError_En(parsed.Code())));
	}
	if (!root.IsObject() || !root.HasMember("format") || !root["format"].IsString())
	{
		throw std::runtime_error("Griffin overlay root is not an object");
	}

	GriffinOverlay result;
	if (root["format"].GetString() != std::string("griffin-analysis-overlay-v1"))
	{
		throw std::runtime_error("unsupported Griffin overlay format");
	}
	auto& model = requiredMember(root, "addressModel");
	if (!model.IsObject())
	{
		throw std::runtime_error("Griffin overlay addressModel is not an object");
	}
	result._imageSize = jsonAddress(requiredMember(model, "imageSize"), "imageSize");
	if (result._imageSize == 0)
	{
		throw std::runtime_error("empty Griffin overlay imageSize");
	}
	for (const char* name : {"staticImageBase", "runtimeImageBase", "preferredTraceBase"})
	{
		auto it = model.FindMember(name);
		if (it != model.MemberEnd())
		{
			result._bases.push_back(jsonAddress(it->value, name));
		}
	}
	if (result._bases.empty())
	{
		throw std::runtime_error("Griffin overlay has no image base");
	}

	auto summary = root.FindMember("summary");
	if (summary != root.MemberEnd() && summary->value.IsObject())
	{
		auto ranges = summary->value.FindMember("ranges");
		if (ranges != summary->value.MemberEnd() && ranges->value.IsArray())
		{
			for (const auto& range : ranges->value.GetArray())
			{
				if (!range.IsObject())
				{
					throw std::runtime_error("Griffin overlay summary range is not an object");
				}
				uint64_t start = jsonAddress(
						requiredMember(range, "startRva"), "summary.ranges[].startRva");
				uint64_t end = jsonAddress(
						requiredMember(range, "endRvaExclusive"),
						"summary.ranges[].endRvaExclusive");
				if (start >= end || end > result._imageSize)
				{
					throw std::runtime_error("invalid Griffin overlay summary range");
				}
				result._observedRanges.push_back({start, end});
			}
		}
	}

	auto& image = requiredMember(root, "image");
	if (!image.IsObject())
	{
		throw std::runtime_error("Griffin overlay image is not an object");
	}
	auto& hash = requiredMember(image, "sha256");
	if (!hash.IsString() || !isSha256(hash.GetString()))
	{
		throw std::runtime_error("invalid Griffin overlay image.sha256");
	}
	result._imageSha256 = lower(hash.GetString());

	auto conflicts = root.FindMember("conflicts");
	if (conflicts != root.MemberEnd() && conflicts->value.IsArray())
	{
		for (const auto& conflict : conflicts->value.GetArray())
		{
			if (conflict.IsString())
			{
				result._conflicts.insert(jsonAddress(conflict, "conflicts[]"));
			}
			else if (conflict.IsObject())
			{
				result._conflicts.insert(jsonAddress(
						requiredMember(conflict, "rva"), "conflicts[].rva"));
			}
			else
			{
				throw std::runtime_error("unsupported Griffin overlay conflict form");
			}
		}
	}

	auto& entries = requiredMember(root, "entries");
	if (!entries.IsArray())
	{
		throw std::runtime_error("Griffin overlay entries is not an array");
	}
	for (const auto& entry : entries.GetArray())
	{
		if (!entry.IsObject())
		{
			throw std::runtime_error("Griffin overlay entry is not an object");
		}
		auto eligible = entry.FindMember("analysisEligible");
		if (eligible == entry.MemberEnd()
				|| !eligible->value.IsBool()
				|| !eligible->value.GetBool())
		{
			continue;
		}
		uint64_t rva = jsonAddress(requiredMember(entry, "rva"), "rva");
		if (result._conflicts.count(rva))
		{
			continue;
		}
		auto& dataText = requiredMember(entry, "data");
		if (!dataText.IsString())
		{
			throw std::runtime_error("Griffin overlay data is not a string");
		}
		auto data = parseHex(dataText.GetString());
		auto& length = requiredMember(entry, "length");
		if (!length.IsUint64() || length.GetUint64() != data.size())
		{
			throw std::runtime_error("Griffin overlay data length mismatch");
		}
		if (rva >= result._imageSize || data.size() > result._imageSize - rva)
		{
			throw std::runtime_error("Griffin overlay entry is outside the image");
		}
		auto& entryHash = requiredMember(entry, "imageSha256");
		if (!entryHash.IsString() || lower(entryHash.GetString()) != result._imageSha256)
		{
			continue;
		}

		auto inserted = result._entries.emplace(rva, Entry{data});
		if (!inserted.second && inserted.first->second.data != data)
		{
			throw std::runtime_error("conflicting Griffin overlay entry variants");
		}
		for (std::size_t i = 0; i < data.size(); ++i)
		{
			auto byte = result._uniqueBytes.emplace(rva + i, data[i]);
			if (!byte.second && byte.first->second != data[i])
			{
				throw std::runtime_error("conflicting Griffin overlay bytes");
			}
		}
	}
	for (const auto& range : result._observedRanges)
	{
		auto it = result._entries.lower_bound(range.startRva);
		if (it == result._entries.end() || it->first >= range.endRva)
		{
			// Without at least one proved instruction there is no evidence that
			// the whole range is dead; retain the ordinary static fallback.
			continue;
		}
		uint64_t first = it->first;
		uint64_t lastEnd = first;
		for (; it != result._entries.end() && it->first < range.endRva; ++it)
		{
			lastEnd = std::max(lastEnd, it->first + it->second.data.size());
		}
		if (first > range.startRva)
		{
			result._nonExecutedRanges.push_back({range.startRva, first});
		}
		if (lastEnd < range.endRva)
		{
			result._nonExecutedRanges.push_back({lastEnd, range.endRva});
		}
	}
	return result;
}

bool GriffinOverlay::checkImageSha256(const std::string& actualSha256) const
{
	return !actualSha256.empty() && lower(actualSha256) == _imageSha256;
}

std::size_t GriffinOverlay::applyTo(loader::Image& image, uint64_t imageBase) const
{
	if (std::find(_bases.begin(), _bases.end(), imageBase) == _bases.end())
	{
		throw std::runtime_error("Griffin overlay image base mismatch");
	}
	for (const auto& item : _entries)
	{
		if (!image.setXBytes(imageBase + item.first, item.second.data))
		{
			throw std::runtime_error("can not apply Griffin overlay to image");
		}
	}
	return _entries.size();
}

std::optional<uint64_t> GriffinOverlay::getRequiredEnd(uint64_t rva) const
{
	auto it = _entries.find(rva);
	if (it == _entries.end())
	{
		return std::nullopt;
	}
	return rva + it->second.data.size();
}

std::optional<uint64_t> GriffinOverlay::getRequiredRangeEnd(
		uint64_t startRva,
		uint64_t currentEndRva) const
{
	std::optional<uint64_t> result;
	for (const auto& item : _entries)
	{
		if (item.first != startRva
				&& (item.first < startRva || item.first >= currentEndRva))
		{
			continue;
		}
		uint64_t end = item.first + item.second.data.size();
		if (!result || end > *result)
		{
			result = end;
		}
	}
	return result;
}

std::vector<uint64_t> GriffinOverlay::getEntryStarts(
		uint64_t startAddress,
		uint64_t endAddress) const
{
	std::vector<uint64_t> result;
	for (auto base : _bases)
	{
		if (startAddress < base || startAddress - base >= _imageSize)
		{
			continue;
		}
		uint64_t startRva = startAddress - base;
		uint64_t endRva = endAddress > base ? endAddress - base : 0;
		for (auto it = _entries.lower_bound(startRva);
				it != _entries.end() && it->first < endRva; ++it)
		{
			result.push_back(base + it->first);
		}
	}
	return result;
}

bool GriffinOverlay::isEntryStart(uint64_t address) const
{
	for (auto base : _bases)
	{
		if (address >= base && address - base < _imageSize)
		{
			return _entries.count(address - base) != 0;
		}
	}
	return false;
}

std::optional<std::pair<uint64_t, uint64_t>> GriffinOverlay::getExecutedBounds(
		uint64_t startAddress,
		uint64_t endAddress) const
{
	for (auto base : _bases)
	{
		if (startAddress < base || startAddress - base >= _imageSize)
		{
			continue;
		}
		uint64_t startRva = startAddress - base;
		uint64_t endRva = endAddress > base ? endAddress - base : 0;
		for (const auto& range : _observedRanges)
		{
			if (startRva < range.startRva || startRva >= range.endRva)
			{
				continue;
			}
			// Selected ranges use an inclusive last-byte address, while the
			// overlay summary uses an exclusive end. Also accept an already
			// exclusive end by saturating at the observed range boundary.
			uint64_t effectiveEnd = endRva >= range.endRva
					? range.endRva : std::min(endRva + 1, range.endRva);
			auto it = _entries.lower_bound(std::max(startRva, range.startRva));
			if (it == _entries.end() || it->first >= effectiveEnd)
			{
				continue;
			}
			uint64_t first = it->first;
			uint64_t lastEnd = first;
			for (; it != _entries.end() && it->first < effectiveEnd; ++it)
			{
				lastEnd = std::max(lastEnd, it->first + it->second.data.size());
			}
			return std::make_pair(base + first, base + lastEnd);
		}
	}
	return std::nullopt;
}

bool GriffinOverlay::isNonExecuted(uint64_t address) const
{
	for (auto base : _bases)
	{
		if (address < base || address - base >= _imageSize)
		{
			continue;
		}
		uint64_t rva = address - base;
		for (const auto& range : _nonExecutedRanges)
		{
			if (range.startRva <= rva && rva < range.endRva)
			{
				return true;
			}
		}
	}
	return false;
}

std::size_t GriffinOverlay::getNonExecutedBoundaryByteCount() const
{
	std::size_t result = 0;
	for (const auto& range : _nonExecutedRanges)
	{
		result += range.endRva - range.startRva;
	}
	return result;
}

std::size_t GriffinOverlay::getEntryCount() const
{
	return _entries.size();
}

std::size_t GriffinOverlay::getAppliedByteCount() const
{
	return _uniqueBytes.size();
}

std::size_t GriffinOverlay::getConflictCount() const
{
	return _conflicts.size();
}

} // namespace bin2llvmir
} // namespace retdec
