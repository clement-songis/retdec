/**
* @file tests/bin2llvmir/providers/griffin_witness_validation_tests.cpp
* @brief Reproducible one-instruction Griffin output validation.
* @copyright (c) 2026 RE Vanguard fork, licensed under the MIT license
*/

#include <algorithm>
#include <memory>
#include <sstream>
#include <string>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/optimizations/value_protect/value_protect.h"
#include "retdec/bin2llvmir/optimizations/writer_bc/writer_bc.h"
#include "retdec/bin2llvmir/optimizations/writer_dsm/writer_dsm.h"
#include "retdec/bin2llvmir/optimizations/writer_ll/writer_ll.h"
#include "retdec/fileformat/types/sec_seg/section.h"
#include "retdec/loader/image_factory.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {
namespace {

constexpr uint64_t TraceBase = 0x140000000;
constexpr uint64_t WitnessRva = 0x2a9881;
constexpr uint64_t WitnessAddress = TraceBase + WitnessRva;

bool isVolatileDataStore(const Instruction& instruction)
{
	auto* store = dyn_cast<StoreInst>(&instruction);
	return store && store->isVolatile()
			&& !isa<GlobalVariable>(store->getPointerOperand()->stripPointerCasts());
}

std::size_t countVolatileDataStores(Module& module)
{
	std::size_t count = 0;
	for (auto& function : module)
	{
		count += std::count_if(
				inst_begin(function),
				inst_end(function),
				isVolatileDataStore);
	}
	return count;
}

} // namespace

class GriffinWitnessValidationTests: public LlvmIrTests
{
	protected:
		struct Result
		{
			std::string dsm;
			std::string llvm;
			std::size_t decodedStores = 0;
			std::size_t finalStores = 0;
			std::size_t parsedLlvmStores = 0;
			std::size_t bitcodeStores = 0;
		};

		Result runOneInstruction(bool enableOverlay)
		{
			parseInput("");
			const std::uint8_t original[] = {0x90}; // nop; overlay changes it to push rbx
			auto format = std::make_shared<fileformat::RawDataFormat>(original, 1);
			format->setBaseAddress(WitnessAddress);
			auto* section = const_cast<fileformat::Section*>(format->getSection(0));
			section->setName(".text");
			section->setType(fileformat::Section::Type::CODE);
			auto loadedImage = loader::createImage(format);
			if (!loadedImage)
			{
				throw std::runtime_error("failed to create one-byte test image");
			}
			loadedImage->setBaseAddress(TraceBase);

			auto inputConfig = config::Config::fromJsonString(R"({
				"architecture": {
					"bitSize": 64,
					"endian": "little",
					"name": "x86-64"
				}
			})");
			auto config = Config::fromConfig(module.get(), inputConfig);
			auto& parameters = config.getConfig().parameters;
			parameters.setEntryPoint(WitnessAddress);
			parameters.setSectionVMA(WitnessAddress);
			parameters.setIsDetectStaticCode(false);
			if (enableOverlay)
			{
				parameters.setGriffinOverlay(RETDEC_GRIFFIN_OVERLAY_WITNESS_TEST);
			}

			auto* abi = AbiProvider::addAbi(module.get(), &config);
			FileImage image(module.get(), std::move(loadedImage), &config);
			NameContainer names(module.get(), &config, nullptr, &image, nullptr);
			Decoder decoder;
			decoder.runOnModuleCustom(
					*module, &config, &image, nullptr, &names, abi);

			Result result;
			result.decodedStores = countVolatileDataStores(*module);
			EXPECT_FALSE(verifyModule(*module, &errs()));

			// This is the production ordering: protect early, emit DSM, remove
			// assembly mapping, unprotect, then emit final LLVM and bitcode.
			ValueProtect valueProtect;
			valueProtect.runOnModuleCustom(*module, &config, abi);
			std::stringstream dsm;
			DsmWriter dsmWriter;
			dsmWriter.runOnModuleCustom(*module, &config, &image, abi, dsm);
			result.dsm = dsm.str();
			AsmInstructionRemover asmRemover;
			asmRemover.runOnModuleCustom(*module);
			valueProtect.runOnModuleCustom(*module, &config, abi);

			result.finalStores = countVolatileDataStores(*module);
			EXPECT_FALSE(verifyModule(*module, &errs()));

			SmallString<128> llvmPath;
			SmallString<128> bitcodePath;
			auto llvmError = sys::fs::createTemporaryFile(
					"retdec-griffin-validation", "ll", llvmPath);
			auto bitcodeError = sys::fs::createTemporaryFile(
					"retdec-griffin-validation", "bc", bitcodePath);
			EXPECT_FALSE(llvmError) << llvmError.message();
			EXPECT_FALSE(bitcodeError) << bitcodeError.message();
			if (!llvmError && !bitcodeError)
			{
				parameters.setOutputLlvmirFile(llvmPath.str().str());
				parameters.setOutputBitcodeFile(bitcodePath.str().str());
				ConfigProvider::addConfig(module.get(), config.getConfig());
				LlvmIrWriter llvmWriter;
				llvmWriter.runOnModule(*module);
				BitcodeWriter bitcodeWriter;
				bitcodeWriter.runOnModule(*module);

				auto llvmBuffer = MemoryBuffer::getFile(llvmPath);
				EXPECT_TRUE(static_cast<bool>(llvmBuffer)) << llvmBuffer.getError().message();
				if (llvmBuffer)
				{
					result.llvm = (*llvmBuffer)->getBuffer().str();
					LLVMContext llvmContext;
					SMDiagnostic parseError;
					auto parsedLlvm = parseIR(
							(*llvmBuffer)->getMemBufferRef(), parseError, llvmContext);
					EXPECT_NE(nullptr, parsedLlvm) << parseError.getMessage().str();
					if (parsedLlvm)
					{
						EXPECT_FALSE(verifyModule(*parsedLlvm, &errs()));
						result.parsedLlvmStores = countVolatileDataStores(*parsedLlvm);
					}
				}

				auto bitcodeBuffer = MemoryBuffer::getFile(bitcodePath);
				EXPECT_TRUE(static_cast<bool>(bitcodeBuffer))
						<< bitcodeBuffer.getError().message();
				if (bitcodeBuffer)
				{
					LLVMContext bitcodeContext;
					auto bitcodeModule = parseBitcodeFile(
							(*bitcodeBuffer)->getMemBufferRef(), bitcodeContext);
					EXPECT_TRUE(static_cast<bool>(bitcodeModule));
					if (bitcodeModule)
					{
						EXPECT_FALSE(verifyModule(**bitcodeModule, &errs()));
						result.bitcodeStores = countVolatileDataStores(**bitcodeModule);
					}
				}
			}
			sys::fs::remove(llvmPath);
			sys::fs::remove(bitcodePath);
			return result;
		}
};

TEST_F(GriffinWitnessValidationTests, overlayPushSurvivesDsmFinalLlvmAndBitcode)
{
	auto result = runOneInstruction(true);

	EXPECT_NE(std::string::npos, result.dsm.find("53"));
	EXPECT_NE(std::string::npos, result.dsm.find("push"));
	EXPECT_EQ(std::string::npos, result.dsm.find("nop"));
	EXPECT_EQ(1, result.decodedStores);
	EXPECT_EQ(result.decodedStores, result.finalStores);
	EXPECT_NE(std::string::npos, result.llvm.find("store volatile"));
	EXPECT_EQ(result.finalStores, result.parsedLlvmStores);
	EXPECT_EQ(result.finalStores, result.bitcodeStores);
}

TEST_F(GriffinWitnessValidationTests, baselineWithoutOverlayDoesNotInventDataStore)
{
	auto result = runOneInstruction(false);

	EXPECT_NE(std::string::npos, result.dsm.find("90"));
	EXPECT_NE(std::string::npos, result.dsm.find("nop"));
	EXPECT_EQ(std::string::npos, result.dsm.find("push"));
	EXPECT_EQ(0, result.decodedStores);
	EXPECT_EQ(0, result.finalStores);
	EXPECT_EQ(0, result.parsedLlvmStores);
	EXPECT_EQ(0, result.bitcodeStores);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
