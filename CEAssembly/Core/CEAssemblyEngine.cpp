#include "CEAssemblyEngine.h"
#include "Utils/DebugHelper.h"
#include "CEScript.h"
#include "Symbol/SymbolManager.h"
#include "Scanner/PatternScanner.h"
#include "MemoryManager.h"
#include "Parser/CEScriptParser.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <set>
#include <map>
#include <cctype>

bool isX64RegisterName(const std::string& token) {
	static const std::regex regPattern(
		R"(^(r(1[0-5]|[8-9]|[abcd]x|sp|bp|si|di)|e[a-d]x|e(si|di|bp|sp)|[abcd][hl]|[rs]i|[rs]p|rip|xmm\d+|ymm\d+|st\d+)$)",
		std::regex::icase);
	return std::regex_match(token, regPattern);
}

CEAssemblyEngine::CEAssemblyEngine()
	: m_memoryManager(std::make_unique<MemoryManager>())
	, m_patternScanner(std::make_unique<PatternScanner>())
	, m_symbolManager(std::make_unique<SymbolManager>())
	, m_parser(std::make_unique<CEScriptParser>())
	, m_ksEngine(nullptr)
	, m_currentAddress(0)
	, m_currentScript(nullptr) {

	LOG_INFO("CEAssemblyEngine constructor called");

	// Initialize Keystone
	ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &m_ksEngine);
	if (err != KS_ERR_OK) {
		LOG_ERROR_F("Failed to initialize Keystone engine: %s", ks_strerror(err));
	}
	else {
		LOG_INFO("Keystone engine initialized successfully (x64 mode)");
	}
}

CEAssemblyEngine::~CEAssemblyEngine() {
	LOG_INFO("CEAssemblyEngine destructor called");
	if (m_ksEngine) {
		ks_close(m_ksEngine);
		LOG_INFO("Keystone engine closed");
	}
}

bool CEAssemblyEngine::AttachToProcess(DWORD pid) {
	LOG_INFO_F("Attaching to process with PID: %d", pid);
	if (m_memoryManager->AttachToProcess(pid)) {
		m_patternScanner->SetProcessManager(m_memoryManager.get());
		return true;
	}

	m_lastError = "Failed to attach to process";
	return false;
}

bool CEAssemblyEngine::AttachToProcess(const std::string& processName) {
	LOG_INFO_F("Attempting to attach to process: %s", processName.c_str());

	DWORD pid = MemoryManager::FindProcessByName(processName);
	if (pid == 0) {
		LOG_ERROR_F("Process '%s' not found", processName.c_str());
		m_lastError = "Process not found: " + processName;
		return false;
	}

	LOG_INFO_F("Found process '%s' with PID: %d", processName.c_str(), pid);
	return AttachToProcess(pid);
}

void CEAssemblyEngine::DetachFromProcess() {
	m_memoryManager->DetachFromProcess();
	m_patternScanner->SetProcessManager(nullptr);
}

bool CEAssemblyEngine::IsAttached() const {
	return m_memoryManager->IsAttached();
}

DWORD CEAssemblyEngine::GetTargetPID() const {
	return m_memoryManager->GetPID();
}

std::shared_ptr<CEScript> CEAssemblyEngine::CreateScript(const std::string& name) {
	LOG_INFO_F("Creating new script: '%s'", name.empty() ? "<unnamed>" : name.c_str());
	auto script = std::make_shared<CEScript>(this);

	std::string scriptName = name;
	if (scriptName.empty()) {
		scriptName = "Script_" + std::to_string(m_scripts.size() + 1);
	}

	script->SetName(scriptName);
	m_scripts[scriptName] = script;
	LOG_DEBUG_F("Total scripts: %zu", m_scripts.size());
	return script;
}

std::shared_ptr<CEScript> CEAssemblyEngine::GetScript(const std::string& name) {
	auto it = m_scripts.find(name);
	if (it != m_scripts.end()) {
		return it->second;
	}
	return nullptr;
}

void CEAssemblyEngine::AddPatch(uintptr_t address,
	const std::vector<uint8_t>& originalBytes,
	const std::vector<uint8_t>& newBytes) {
	PatchInfo patch;
	patch.address = address;
	patch.originalBytes = originalBytes;
	patch.newBytes = newBytes;
	m_patches.push_back(patch);
}

bool CEAssemblyEngine::ProcessEnableBlock(const std::vector<std::string>& lines) {
	m_patches.clear();
	m_currentAddress = 0;
	m_anonymousLabels.clear();
	m_allLabels.clear();  // Clear all labels

	// First pass: Process commands and establish symbols
	LOG_DEBUG("=== Pass 1: Processing commands ===");
	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::AOBSCANMODULE:
			if (!ProcessAobScanModule(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		case CommandType::ALLOC:
			if (!ProcessAlloc(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		case CommandType::LABEL:
			if (!ProcessLabel(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		case CommandType::REGISTERSYMBOL:
			if (!ProcessRegisterSymbol(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		default:
			break;
		}
	}

	// Second pass: Process assembly and label definitions
	LOG_DEBUG("=== Pass 2: Processing assembly and labels ===");
	std::vector<DelayedInstruction> delayedInstructions;

	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		if (cmd.type == CommandType::ASSEMBLY) {
			if (!line.empty() && line.back() == ':') {
				// Label definition
				std::string labelName = line.substr(0, line.length() - 1);

				// Check for anonymous label
				if (labelName == "@@") {
					m_anonymousLabels.push_back(m_currentAddress);
					m_allLabels[m_currentAddress] = "@@";  // Track in all labels
					LOG_DEBUG_F("Anonymous label @@ at 0x%llX", m_currentAddress);
				}
				else {
					// Handle label+offset syntax (e.g., newmem+200)
					size_t plusPos = labelName.find('+');
					if (plusPos != std::string::npos) {
						std::string baseName = labelName.substr(0, plusPos);
						std::string offsetStr = labelName.substr(plusPos + 1);

						uintptr_t baseAddr = 0;
						if (m_symbolManager->GetSymbolAddress(baseName, baseAddr) && baseAddr != 0) {
							size_t offset = std::stoull(offsetStr, nullptr, 16);
							m_currentAddress = baseAddr + offset;
							LOG_DEBUG_F("Label %s: base=%s(0x%llX) + offset=0x%zX = 0x%llX",
								labelName.c_str(), baseName.c_str(), baseAddr, offset, m_currentAddress);
						}
					}
					else {
						uintptr_t addr = 0;
						if (m_symbolManager->GetSymbolAddress(labelName, addr) && addr != 0) {
							// Label with existing address
							m_currentAddress = addr;
							m_allLabels[m_currentAddress] = labelName;  // Track in all labels
							LOG_DEBUG_F("Label %s: current address = 0x%llX", labelName.c_str(), addr);
						}
						else {
							// New label
							if (m_currentAddress != 0) {
								m_symbolManager->RegisterSymbol(labelName, m_currentAddress, 0, true);
								m_allLabels[m_currentAddress] = labelName;  // Track in all labels
								LOG_DEBUG_F("Label %s: registered at 0x%llX", labelName.c_str(), m_currentAddress);
							}
							else {
								LOG_ERROR_F("Label %s has no context address", labelName.c_str());
								m_lastError = "Label has no context address: " + labelName;
								return false;
							}
						}
					}
				}
			}
			else {
				// Assembly instruction
				uintptr_t instructionAddress = m_currentAddress;
				if (!ProcessAssemblyInstruction(line)) {
					// Processing failed, add to delayed list
					DelayedInstruction delayed;
					delayed.instruction = line;
					delayed.address = instructionAddress;
					delayedInstructions.push_back(delayed);
					LOG_DEBUG_F("Delaying instruction at 0x%llX: %s", instructionAddress, line.c_str());

					// Estimate instruction size for address update
					std::istringstream iss(line);
					std::string op;
					iss >> op;
					std::transform(op.begin(), op.end(), op.begin(), ::tolower);

					if (op == "jmp" || op == "call") {
						m_currentAddress += 5; // Assume E9 jump
					}
					else if (op == "je" || op == "jne" || op == "jg" || op == "jl" || op == "jge" || op == "jle") {
						m_currentAddress += 2; // Short conditional jump
					}
					else if (op == "dd") {
						m_currentAddress += 4;
					}
					else if (op == "dq") {
						m_currentAddress += 8;
					}
					else if (op == "db") {
						m_currentAddress += 1;
					}
					else if (op == "dw") {
						m_currentAddress += 2;
					}
					else {
						m_currentAddress += 4; // Default estimate
					}
				}
			}
		}
	}

	// Third pass: Process delayed instructions
	LOG_DEBUG("=== Pass 3: Processing delayed instructions ===");
	for (const auto& delayed : delayedInstructions) {
		uintptr_t savedAddress = m_currentAddress;
		m_currentAddress = delayed.address;

		if (!ProcessAssemblyInstruction(delayed.instruction)) {
			LOG_ERROR_F("Failed to process delayed instruction at 0x%llX: %s",
				delayed.address, delayed.instruction.c_str());
			m_lastError = "Failed to process delayed instruction: " + delayed.instruction;
			return false;
		}

		m_currentAddress = savedAddress;
	}

	LOG_DEBUG("=== Enable block processing completed ===");
	return true;
}

bool CEAssemblyEngine::ProcessAssemblyInstruction(const std::string& line) {
	// Validate current address
	if (m_currentAddress == 0) {
		LOG_ERROR("Cannot process instruction without current address");
		m_lastError = "No current address set";
		return false;
	}

	LOG_DEBUG_F("Processing instruction: %s", line.c_str());

	// Extract opcode for special handling
	std::string opcode;
	std::istringstream lineStream(line);
	lineStream >> opcode;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// Special handling for NOP instruction
	if (opcode == "nop") {
		int nopCount = 1;

		// Try to read count parameter
		std::string countStr;
		if (lineStream >> countStr) {
			try {
				nopCount = std::stoi(countStr);
			}
			catch (...) {
				nopCount = 1;
			}
		}

		// Generate NOP bytes
		std::vector<uint8_t> nopBytes(nopCount, 0x90);
		LOG_DEBUG_F("Generating %d NOP byte(s)", nopCount);

		return WriteBytes(nopBytes);
	}

	// Special handling for data definition directives
	if (opcode == "dd" || opcode == "db" || opcode == "dw" || opcode == "dq") {
		return ProcessDataDirective(line);
	}

	// Special handling for float/double immediate values
	std::string processedLine = line;

	// Convert (float)value syntax
	size_t floatPos = processedLine.find("(float)");
	if (floatPos != std::string::npos) {
		// Extract the value after (float)
		size_t valueStart = floatPos + 7; // length of "(float)"
		size_t valueEnd = valueStart;

		// Find end of value
		while (valueEnd < processedLine.length() &&
			(std::isdigit(processedLine[valueEnd]) ||
				processedLine[valueEnd] == '.' ||
				processedLine[valueEnd] == '-')) {
			valueEnd++;
		}

		std::string floatValueStr = processedLine.substr(valueStart, valueEnd - valueStart);
		float floatValue = std::stof(floatValueStr);

		// For mov instructions with float, we need to handle this specially
		if (opcode == "mov") {
			// Convert to bytes
			uint32_t floatBits = *reinterpret_cast<uint32_t*>(&floatValue);

			// Extract destination
			size_t commaPos = processedLine.find(',');
			if (commaPos != std::string::npos) {
				std::string dest = processedLine.substr(3, commaPos - 3);
				dest.erase(0, dest.find_first_not_of(" \t"));
				dest.erase(dest.find_last_not_of(" \t") + 1);

				// Replace symbols in destination
				dest = ReplaceSymbols(dest);

				// Build new instruction
				std::stringstream newInst;
				newInst << "mov dword ptr " << dest << ", 0x" << std::hex << floatBits;
				processedLine = newInst.str();

				LOG_DEBUG_F("Converted float mov: %s", processedLine.c_str());
			}
		}
	}

	// Always perform symbol replacement first
	processedLine = ReplaceSymbols(processedLine);

	// Log transformation if changed
	if (processedLine != line) {
		LOG_DEBUG_F("Symbol replacement: %s -> %s", line.c_str(), processedLine.c_str());
	}

	// Special handling for @f and @b labels
	if (processedLine.find("@f") != std::string::npos ||
		processedLine.find("@b") != std::string::npos) {
		return ProcessCESpecialJump(line); // Use original line, not processed
	}

	// Special handling for mov instructions with large immediates
	if (opcode == "mov" && processedLine.find(",0x") != std::string::npos) {
		return ProcessSpecialMovInstruction(processedLine);
	}

	// Special handling for cmp instructions with immediates
	if (opcode == "cmp" && processedLine.find(",0x") != std::string::npos) {
		// Force dword ptr for cmp with immediates
		size_t bracketPos = processedLine.find('[');
		if (bracketPos != std::string::npos) {
			processedLine.insert(bracketPos, "dword ptr ");
			LOG_DEBUG_F("Added dword ptr: %s", processedLine.c_str());
		}
	}

	// Prepare for assembly
	unsigned char* machineCode = nullptr;
	size_t codeSize = 0;
	size_t statements = 0;

	// Assemble the processed instruction
	LOG_TRACE_F("Assembling at 0x%llX: %s", m_currentAddress, processedLine.c_str());

	int asmResult = ks_asm(m_ksEngine,
		processedLine.c_str(),
		m_currentAddress,
		&machineCode,
		&codeSize,
		&statements);

	// Handle assembly result
	if (asmResult == KS_ERR_OK) {
		if (codeSize > 0) {
			// Success with generated code
			std::vector<uint8_t> bytes(machineCode, machineCode + codeSize);
			ks_free(machineCode);

			LOG_DEBUG_F("Assembly successful: %zu bytes", codeSize);
			return WriteBytes(bytes);
		}
		else {
			// Success but no code (label or directive)
			LOG_DEBUG("No machine code generated (label/directive)");
			return true;
		}
	}

	// Assembly failed
	ks_err error = ks_errno(m_ksEngine);
	LOG_DEBUG_F("Assembly failed: %s", ks_strerror(error));

	// Check if it's a jump instruction with unresolved symbol
	std::istringstream processedStream(processedLine);
	std::string processedOp;
	processedStream >> processedOp;
	std::transform(processedOp.begin(), processedOp.end(), processedOp.begin(), ::tolower);

	// Handle jump/call instructions
	if (processedOp == "jmp" || processedOp == "call" ||
		(processedOp.size() > 0 && processedOp[0] == 'j')) {

		std::string target;
		processedStream >> target;

		// Check if target is a symbol
		if (!target.empty() && (std::isalpha(target[0]) || target[0] == '_')) {
			uintptr_t targetAddr = 0;

			if (m_symbolManager->GetSymbolAddress(target, targetAddr)) {
				if (targetAddr != 0) {
					// Generate jump instruction
					LOG_DEBUG_F("Generating jump to %s (0x%llX)", target.c_str(), targetAddr);
					return ProcessJumpInstruction(processedOp, targetAddr);
				}
				else {
					// Forward reference
					LOG_DEBUG_F("Forward reference: %s", target.c_str());
					return false;
				}
			}
		}
	}

	// Final error
	LOG_ERROR_F("Failed to assemble: %s", processedLine.c_str());
	m_lastError = std::string("Assembly error: ") + ks_strerror(error);
	return false;
}

// New helper function for special mov instructions
bool CEAssemblyEngine::ProcessSpecialMovInstruction(const std::string& line) {
	// Parse the instruction
	std::istringstream iss(line);
	std::string op, dest, src;
	iss >> op;

	// Get destination and source
	size_t commaPos = line.find(',');
	if (commaPos == std::string::npos) return false;

	dest = line.substr(op.length(), commaPos - op.length());
	src = line.substr(commaPos + 1);

	// Trim whitespace
	dest.erase(0, dest.find_first_not_of(" \t"));
	dest.erase(dest.find_last_not_of(" \t") + 1);
	src.erase(0, src.find_first_not_of(" \t"));
	src.erase(src.find_last_not_of(" \t") + 1);

	// Check if immediate value is too large
	if (src.find("0x") == 0) {
		try {
			unsigned long long value = std::stoull(src, nullptr, 16);

			// If value > 32 bits, we need special handling
			if (value > 0xFFFFFFFF) {
				LOG_ERROR_F("Immediate value too large for mov: %s", src.c_str());
				return false;
			}

			// For 32-bit values, add dword ptr if needed
			if (dest.find('[') != std::string::npos && dest.find("ptr") == std::string::npos) {
				std::string newLine = op + " dword ptr " + dest + "," + src;
				LOG_DEBUG_F("Trying with dword ptr: %s", newLine.c_str());

				unsigned char* machineCode = nullptr;
				size_t codeSize = 0;
				size_t statements = 0;

				int asmResult = ks_asm(m_ksEngine,
					newLine.c_str(),
					m_currentAddress,
					&machineCode,
					&codeSize,
					&statements);

				if (asmResult == KS_ERR_OK && codeSize > 0) {
					std::vector<uint8_t> bytes(machineCode, machineCode + codeSize);
					ks_free(machineCode);
					return WriteBytes(bytes);
				}
			}
		}
		catch (...) {
			// Not a valid number
		}
	}

	return false;
}

bool CEAssemblyEngine::ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr) {
	std::string op = opcode;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "jmp") {
		// Calculate relative offset
		int64_t offset = targetAddr - (m_currentAddress + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// E9 relative jump
			std::vector<uint8_t> jumpBytes = {
				0xE9,
				static_cast<uint8_t>(offset & 0xFF),
				static_cast<uint8_t>((offset >> 8) & 0xFF),
				static_cast<uint8_t>((offset >> 16) & 0xFF),
				static_cast<uint8_t>((offset >> 24) & 0xFF)
			};

			LOG_DEBUG_F("Generated E9 jump from 0x%llX to 0x%llX (offset: %lld)",
				m_currentAddress, targetAddr, offset);
			return WriteBytes(jumpBytes);
		}
		else {
			// Distance too far, use FF25 absolute jump
			// FF 25 00 00 00 00 [8 byte target address]
			std::vector<uint8_t> jumpBytes = {
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // FF 25 00000000 (jmp [rip+0])
			};

			// Add 8 byte target address
			for (int i = 0; i < 8; ++i) {
				jumpBytes.push_back((targetAddr >> (i * 8)) & 0xFF);
			}

			LOG_DEBUG_F("Generated FF25 absolute jump from 0x%llX to 0x%llX (distance: %lld)",
				m_currentAddress, targetAddr, offset);
			return WriteBytes(jumpBytes);
		}
	}
	else if (op == "call") {
		// call instruction
		int64_t offset = targetAddr - (m_currentAddress + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			std::vector<uint8_t> callBytes = {
				0xE8,
				static_cast<uint8_t>(offset & 0xFF),
				static_cast<uint8_t>((offset >> 8) & 0xFF),
				static_cast<uint8_t>((offset >> 16) & 0xFF),
				static_cast<uint8_t>((offset >> 24) & 0xFF)
			};

			return WriteBytes(callBytes);
		}
		else {
			// Call distance too far
			LOG_ERROR_F("Call distance too far: %lld", offset);
			return false;
		}
	}
	// Handle conditional jumps
	else if (op.length() > 0 && op[0] == 'j') {
		// Map of conditional jump mnemonics to their opcodes
		std::map<std::string, uint8_t> jumpOpcodes = {
			{"je", 0x74}, {"jz", 0x74},
			{"jne", 0x75}, {"jnz", 0x75},
			{"jg", 0x7F}, {"jnle", 0x7F},
			{"jge", 0x7D}, {"jnl", 0x7D},
			{"jl", 0x7C}, {"jnge", 0x7C},
			{"jle", 0x7E}, {"jng", 0x7E},
			{"ja", 0x77}, {"jnbe", 0x77},
			{"jae", 0x73}, {"jnb", 0x73}, {"jnc", 0x73},
			{"jb", 0x72}, {"jnae", 0x72}, {"jc", 0x72},
			{"jbe", 0x76}, {"jna", 0x76}
		};

		auto it = jumpOpcodes.find(op);
		if (it != jumpOpcodes.end()) {
			return GenerateConditionalJump(it->second, targetAddr);
		}
	}

	return false;
}

bool CEAssemblyEngine::WriteBytes(const std::vector<uint8_t>& bytes) {
	if (bytes.empty() || m_currentAddress == 0) return false;

	// Save original bytes
	std::vector<uint8_t> originalBytes(bytes.size());
	m_memoryManager->ReadMemory(m_currentAddress, originalBytes.data(), bytes.size());

	// Write new bytes
	DWORD oldProtect;
	if (m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(),
		PAGE_EXECUTE_READWRITE, &oldProtect)) {
		bool success = m_memoryManager->WriteMemory(m_currentAddress, bytes.data(), bytes.size());
		m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(), oldProtect, &oldProtect);

		if (success) {
			// Record patch
			AddPatch(m_currentAddress, originalBytes, bytes);
			LOG_TRACE_F("Wrote %zu bytes at 0x%llX", bytes.size(), m_currentAddress);

			// Update current address
			m_currentAddress += bytes.size();
			return true;
		}
	}

	return false;
}

bool CEAssemblyEngine::ProcessAobScanModule(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.size() < 3) {
		m_lastError = "Invalid aobscanmodule syntax";
		return false;
	}

	std::string symbolName = cmd.parameters[0];
	std::string moduleName = cmd.parameters[1];

	std::string pattern;
	for (size_t i = 2; i < cmd.parameters.size(); ++i) {
		if (!pattern.empty()) pattern += " ";
		pattern += cmd.parameters[i];
	}

	uintptr_t address = m_patternScanner->ScanModule(moduleName, pattern);
	if (address == 0) {
		m_lastError = "Pattern not found";
		return false;
	}

	m_symbolManager->RegisterSymbol(symbolName, address);
	LOG_INFO_F("Symbol '%s' registered at 0x%llX", symbolName.c_str(), address);

	auto capturedVars = m_patternScanner->GetCapturedVariables();
	for (const auto& [name, data] : capturedVars) {
		m_symbolManager->RegisterCapturedData(name, data);
	}
	m_patternScanner->ClearCapturedVariables();

	return true;
}

bool CEAssemblyEngine::ProcessAlloc(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.size() < 2) {
		m_lastError = "Invalid alloc syntax";
		return false;
	}

	std::string allocName = cmd.parameters[0];

	size_t size = 0;
	std::string sizeStr = cmd.parameters[1];
	if (sizeStr[0] == '$') {
		size = std::stoull(sizeStr.substr(1), nullptr, 16);
	}
	else {
		size = std::stoull(sizeStr, nullptr, 10);
	}

	// Get near address
	uintptr_t nearAddress = 0;
	if (cmd.parameters.size() > 2) {
		m_symbolManager->GetSymbolAddress(cmd.parameters[2], nearAddress);
	}

	uintptr_t allocAddr = 0;

	if (nearAddress != 0) {
		// Strategy 1: Try to allocate near the address first
		allocAddr = m_memoryManager->AllocateNear(nearAddress, size, allocName);

		if (allocAddr != 0) {
			// Check if distance is within E9 range (±2GB)
			int64_t distance = static_cast<int64_t>(allocAddr) - static_cast<int64_t>(nearAddress);
			if (distance >= -0x80000000LL && distance <= 0x7FFFFFFFLL) {
				LOG_INFO_F("Memory allocated near: %s at 0x%llX (distance from 0x%llX: %lld bytes, E9 compatible)",
					allocName.c_str(), allocAddr, nearAddress, distance);
			}
			else {
				LOG_INFO_F("Memory allocated far: %s at 0x%llX (distance from 0x%llX: %lld bytes, needs FF25)",
					allocName.c_str(), allocAddr, nearAddress, distance);

				// Distance too far, release and try low address
				m_memoryManager->Deallocate(allocName);

				// Strategy 2: Request low address for FF25 jump
				allocAddr = m_memoryManager->AllocateNear(0x10000000, size, allocName);
				if (allocAddr != 0) {
					LOG_INFO_F("Memory allocated low: %s at 0x%llX (will use FF25 jump)",
						allocName.c_str(), allocAddr);
				}
			}
		}
	}
	else {
		// No near address, directly request low address
		allocAddr = m_memoryManager->AllocateNear(0x10000000, size, allocName);
		LOG_INFO_F("Memory allocated: %s at 0x%llX (no near address specified)",
			allocName.c_str(), allocAddr);
	}

	if (allocAddr == 0) {
		m_lastError = "Failed to allocate memory";
		return false;
	}

	m_symbolManager->RegisterSymbol(allocName, allocAddr, size);
	return true;
}

bool CEAssemblyEngine::ProcessLabel(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid label syntax";
		return false;
	}

	std::string labelName = cmd.parameters[0];
	m_symbolManager->RegisterSymbol(labelName, 0, 0, true);
	LOG_DEBUG_F("Label '%s' declared", labelName.c_str());
	return true;
}

bool CEAssemblyEngine::ProcessRegisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid registersymbol syntax";
		return false;
	}
	// This would implement global symbol registration logic
	return true;
}

std::string CEAssemblyEngine::ReplaceSymbols(const std::string& line) {
	LOG_TRACE_F("Symbol replacement input: %s", line.c_str());

	// Tokenizer state
	enum TokenType {
		TK_WHITESPACE,
		TK_OPCODE,
		TK_REGISTER,
		TK_NUMBER,
		TK_SYMBOL,
		TK_OPERATOR,
		TK_PUNCTUATION,
		TK_SPECIAL,     // For @f, @b
		TK_TYPECAST,    // For (float), (double), etc.
		TK_UNKNOWN
	};

	struct Token {
		TokenType type;
		std::string text;
	};

	std::vector<Token> tokens;
	size_t i = 0;

	// Tokenization phase
	while (i < line.length()) {
		Token token;

		// Whitespace
		if (std::isspace(line[i])) {
			token.type = TK_WHITESPACE;
			while (i < line.length() && std::isspace(line[i])) {
				token.text += line[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// Check for @f, @b (CE special labels) - DON'T convert these
		if (line[i] == '@' && i + 1 < line.length()) {
			if (line[i + 1] == 'f' || line[i + 1] == 'b') {
				token.type = TK_SPECIAL;
				token.text = line.substr(i, 2);
				i += 2;
				tokens.push_back(token);
				LOG_TRACE_F("CE special label: %s", token.text.c_str());
				continue;
			}
		}

		// Check for type casts like (float), (double)
		if (line[i] == '(' && i + 1 < line.length()) {
			size_t closePos = line.find(')', i);
			if (closePos != std::string::npos) {
				std::string content = line.substr(i + 1, closePos - i - 1);
				if (content == "float" || content == "double" || content == "int" ||
					content == "byte" || content == "word" || content == "dword" || content == "qword") {
					token.type = TK_TYPECAST;
					token.text = line.substr(i, closePos - i + 1);
					i = closePos + 1;
					tokens.push_back(token);
					LOG_TRACE_F("Type cast: %s", token.text.c_str());
					continue;
				}
			}
		}

		// Punctuation
		if (line[i] == ',' || line[i] == '[' || line[i] == ']' ||
			line[i] == '(' || line[i] == ')' || line[i] == ':') {
			token.type = TK_PUNCTUATION;
			token.text = line[i++];
			tokens.push_back(token);
			continue;
		}

		// Operators
		if (line[i] == '+' || line[i] == '-' || line[i] == '*') {
			token.type = TK_OPERATOR;
			token.text = line[i++];
			tokens.push_back(token);
			continue;
		}

		// $ prefix (CE hex notation)
		if (line[i] == '$') {
			i++; // Skip $
			token.type = TK_NUMBER;
			std::string hexNum;
			while (i < line.length() && std::isxdigit(line[i])) {
				hexNum += line[i++];
			}
			token.text = "0x" + hexNum;
			tokens.push_back(token);
			LOG_TRACE_F("CE hex: $%s -> %s", hexNum.c_str(), token.text.c_str());
			continue;
		}

		// # prefix (immediate value)
		if (line[i] == '#') {
			i++; // Skip #
			token.type = TK_NUMBER;
			std::string num;
			while (i < line.length() && std::isdigit(line[i])) {
				num += line[i++];
			}
			// Keep as decimal
			token.text = num;
			tokens.push_back(token);
			LOG_TRACE_F("Immediate: #%s -> %s", num.c_str(), token.text.c_str());
			continue;
		}

		// 0x prefix
		if (i + 2 <= line.length() && line[i] == '0' &&
			(line[i + 1] == 'x' || line[i + 1] == 'X')) {
			token.type = TK_NUMBER;
			token.text = "0x";
			i += 2;
			while (i < line.length() && std::isxdigit(line[i])) {
				token.text += line[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// Alphanumeric sequence
		if (std::isalnum(line[i]) || line[i] == '_') {
			std::string word;
			size_t start = i;

			while (i < line.length() && (std::isalnum(line[i]) || line[i] == '_')) {
				word += line[i++];
			}

			// Determine type
			std::string lowerWord = word;
			std::transform(lowerWord.begin(), lowerWord.end(), lowerWord.begin(), ::tolower);

			// First token is usually opcode
			if (tokens.empty() || (tokens.size() > 0 &&
				tokens.back().type == TK_PUNCTUATION && tokens.back().text == ":")) {
				token.type = TK_OPCODE;
			}
			// Check if register
			else if (isX64RegisterName(lowerWord)) {
				token.type = TK_REGISTER;
			}
			// Check if pure number (all hex digits) - but NOT if it's 'f' or 'b' after '@'
			else if (std::all_of(word.begin(), word.end(),
				[](char c) { return std::isxdigit(c); })) {

				// Check if previous token was '@'
				bool afterAt = false;
				if (tokens.size() >= 2) {
					const Token& prevToken = tokens[tokens.size() - 1];
					const Token& prevPrevToken = tokens[tokens.size() - 2];
					if (prevToken.type == TK_OPERATOR && prevToken.text == "@" ||
						(prevPrevToken.type == TK_OPERATOR && prevPrevToken.text == "@" &&
							prevToken.type == TK_WHITESPACE)) {
						afterAt = true;
					}
				}

				if (!afterAt) {
					token.type = TK_NUMBER;
					// Add 0x prefix to all numbers
					token.text = "0x" + word;
					LOG_TRACE_F("Auto-hex: %s -> %s", word.c_str(), token.text.c_str());
					tokens.push_back(token);
					continue;
				}
			}
			// Otherwise it's a symbol
			else {
				token.type = TK_SYMBOL;
			}

			token.text = word;
			tokens.push_back(token);
			continue;
		}

		// Unknown character
		token.type = TK_UNKNOWN;
		token.text = line[i++];
		tokens.push_back(token);
	}

	// Build result
	std::string result;

	for (size_t idx = 0; idx < tokens.size(); idx++) {
		const Token& tok = tokens[idx];

		if (tok.type == TK_SYMBOL) {
			// Check if it's a jump target
			bool isJumpTarget = false;

			// Look backward for opcode
			for (int j = idx - 1; j >= 0; j--) {
				if (tokens[j].type == TK_OPCODE) {
					std::string op = tokens[j].text;
					std::transform(op.begin(), op.end(), op.begin(), ::tolower);
					if (op == "jmp" || op == "call" ||
						(op.length() > 0 && op[0] == 'j')) {
						isJumpTarget = true;
					}
					break;
				}
				else if (tokens[j].type != TK_WHITESPACE) {
					break;
				}
			}

			if (!isJumpTarget) {
				// Try to resolve symbol
				uint64_t capturedVal;
				uintptr_t symbolAddr;

				if (m_symbolManager->GetCapturedValue(tok.text, capturedVal)) {
					result += std::to_string(capturedVal);
					LOG_DEBUG_F("Symbol %s -> captured %llu", tok.text.c_str(), capturedVal);
				}
				else if (m_symbolManager->GetSymbolAddress(tok.text, symbolAddr) &&
					symbolAddr != 0) {
					std::stringstream ss;
					ss << "0x" << std::hex << symbolAddr;
					result += ss.str();
					LOG_DEBUG_F("Symbol %s -> 0x%llX", tok.text.c_str(), symbolAddr);
				}
				else {
					result += tok.text;
				}
			}
			else {
				result += tok.text;
			}
		}
		else {
			result += tok.text;
		}
	}

	LOG_TRACE_F("Symbol replacement output: %s", result.c_str());
	return result;
}

bool CEAssemblyEngine::ProcessDisableBlock(const std::vector<std::string>& lines) {
	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::DB:
			ProcessDbCommand(line);
			break;

		case CommandType::UNREGISTERSYMBOL:
			ProcessUnregisterSymbol(line);
			break;

		case CommandType::DEALLOC:
			ProcessDealloc(line);
			break;

		default:
			break;
		}
	}

	return true;
}

bool CEAssemblyEngine::ProcessDbCommand(const std::string& line) {
	// Parse the label first if present
	if (!line.empty() && line.find(':') != std::string::npos) {
		// Extract label part
		size_t colonPos = line.find(':');
		std::string labelPart = line.substr(0, colonPos);

		// Handle label+offset syntax (e.g., aobplayer+D)
		size_t plusPos = labelPart.find('+');
		if (plusPos != std::string::npos) {
			std::string baseName = labelPart.substr(0, plusPos);
			std::string offsetStr = labelPart.substr(plusPos + 1);

			uintptr_t baseAddr = 0;
			if (m_symbolManager->GetSymbolAddress(baseName, baseAddr) && baseAddr != 0) {
				size_t offset = std::stoull(offsetStr, nullptr, 16);
				m_currentAddress = baseAddr + offset;
				LOG_DEBUG_F("DB at %s: base=%s(0x%llX) + offset=0x%zX = 0x%llX",
					labelPart.c_str(), baseName.c_str(), baseAddr, offset, m_currentAddress);
			}
		}
		else {
			// Regular label
			uintptr_t addr = 0;
			if (m_symbolManager->GetSymbolAddress(labelPart, addr) && addr != 0) {
				m_currentAddress = addr;
				LOG_DEBUG_F("DB at %s: 0x%llX", labelPart.c_str(), addr);
			}
		}
	}

	// Restore original bytes from patch information
	for (const auto& patch : m_patches) {
		if (patch.address == m_currentAddress) {
			DWORD oldProtect;
			if (m_memoryManager->ProtectMemory(patch.address, patch.originalBytes.size(),
				PAGE_EXECUTE_READWRITE, &oldProtect)) {
				m_memoryManager->WriteMemory(patch.address, patch.originalBytes.data(),
					patch.originalBytes.size());
				m_memoryManager->ProtectMemory(patch.address, patch.originalBytes.size(),
					oldProtect, &oldProtect);
				return true;
			}
		}
	}
	return false;
}

bool CEAssemblyEngine::ProcessAssemblyBatch(const std::vector<std::string>& instructions, uintptr_t startAddress) {
	m_currentAddress = startAddress;

	// Try to batch assemble all instructions
	std::string batchAssembly;
	for (const auto& line : instructions) {
		if (!batchAssembly.empty()) {
			batchAssembly += "\n";
		}
		batchAssembly += ReplaceSymbols(line);
	}

	LOG_DEBUG_F("Batch assembly at 0x%llX (%zu instructions):", startAddress, instructions.size());
	LOG_DEBUG_F("Batch content:\n%s", batchAssembly.c_str());

	unsigned char* encode;
	size_t size;
	size_t count;

	if (ks_asm(m_ksEngine, batchAssembly.c_str(), startAddress, &encode, &size, &count) == KS_ERR_OK) {
		std::vector<uint8_t> machineCode(encode, encode + size);
		ks_free(encode);

		bool success = WriteBytes(machineCode);
		LOG_DEBUG_F("Batch assembly result: %zu bytes, success=%d", size, success);
		return success;
	}
	else {
		// Batch failed, try individual processing
		LOG_WARN_F("Batch assembly failed (%s), trying individual instructions",
			ks_strerror(ks_errno(m_ksEngine)));

		m_currentAddress = startAddress;
		for (const auto& line : instructions) {
			if (!ProcessAssemblyInstruction(line)) {
				return false;
			}
		}
		return true;
	}
}

bool CEAssemblyEngine::ProcessUnregisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid unregistersymbol syntax";
		return false;
	}

	m_symbolManager->UnregisterSymbol(cmd.parameters[0]);
	return true;
}

bool CEAssemblyEngine::ProcessDealloc(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid dealloc syntax";
		return false;
	}

	return m_memoryManager->Deallocate(cmd.parameters[0]);
}

// Helper function for data directives
bool CEAssemblyEngine::ProcessDataDirective(const std::string& line) {
	std::istringstream iss(line);
	std::string directive;
	iss >> directive;
	std::transform(directive.begin(), directive.end(), directive.begin(), ::tolower);

	std::vector<uint8_t> dataBytes;

	if (directive == "db") {
		// Define byte
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			// Process the value through symbol replacement
			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid byte value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dw") {
		// Define word (2 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid word value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dd") {
		// Define dword (4 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid dword value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dq") {
		// Define qword (8 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long long val = std::stoull(processedValue, nullptr, 0);
				for (int i = 0; i < 8; i++) {
					dataBytes.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
				}
			}
			catch (...) {
				LOG_ERROR_F("Invalid qword value: %s", value.c_str());
				return false;
			}
		}
	}

	if (!dataBytes.empty()) {
		LOG_DEBUG_F("Data directive %s: %zu bytes", directive.c_str(), dataBytes.size());
		return WriteBytes(dataBytes);
	}

	return false;
}

// Helper function for CE special jumps
bool CEAssemblyEngine::ProcessCESpecialJump(const std::string& line) {
	std::istringstream iss(line);
	std::string opcode;
	iss >> opcode;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	std::string target;
	iss >> target;

	if (target == "@f") {
		// Find next label (anonymous or named)
		uintptr_t nextLabel = FindNextLabel(m_currentAddress);
		if (nextLabel != 0) {
			LOG_DEBUG_F("Resolved @f from 0x%llX to 0x%llX", m_currentAddress, nextLabel);
			return ProcessJumpInstruction(opcode, nextLabel);
		}
		else {
			LOG_DEBUG_F("@f not resolved yet at 0x%llX, delaying", m_currentAddress);
			return false;
		}
	}
	else if (target == "@b") {
		// Find previous label (anonymous or named)
		uintptr_t prevLabel = FindPreviousLabel(m_currentAddress);
		if (prevLabel != 0) {
			LOG_DEBUG_F("Resolved @b from 0x%llX to 0x%llX", m_currentAddress, prevLabel);
			return ProcessJumpInstruction(opcode, prevLabel);
		}
		else {
			LOG_ERROR("@b: no previous label found");
			return false;
		}
	}

	return false;
}

// Helper function to generate conditional jumps
bool CEAssemblyEngine::GenerateConditionalJump(uint8_t opcode, uintptr_t targetAddr) {
	int64_t offset = targetAddr - (m_currentAddress + 2); // Short jump is 2 bytes

	if (offset >= -128 && offset <= 127) {
		// Short jump
		std::vector<uint8_t> jumpBytes = {
			opcode,
			static_cast<uint8_t>(offset & 0xFF)
		};
		LOG_DEBUG_F("Generated short conditional jump (0x%02X) to 0x%llX", opcode, targetAddr);
		return WriteBytes(jumpBytes);
	}
	else {
		// Near jump (0F 8x xx xx xx xx)
		offset = targetAddr - (m_currentAddress + 6); // Near jump is 6 bytes
		std::vector<uint8_t> jumpBytes = {
			0x0F,
			static_cast<uint8_t>(opcode + 0x10), // Convert to near jump opcode
			static_cast<uint8_t>(offset & 0xFF),
			static_cast<uint8_t>((offset >> 8) & 0xFF),
			static_cast<uint8_t>((offset >> 16) & 0xFF),
			static_cast<uint8_t>((offset >> 24) & 0xFF)
		};
		LOG_DEBUG_F("Generated near conditional jump (0F %02X) to 0x%llX", opcode + 0x10, targetAddr);
		return WriteBytes(jumpBytes);
	}
}

uintptr_t CEAssemblyEngine::FindNextAnonymousLabel(uintptr_t fromAddress) {
	for (uintptr_t addr : m_anonymousLabels) {
		if (addr > fromAddress) {
			return addr;
		}
	}
	return 0;
}

uintptr_t CEAssemblyEngine::FindPreviousAnonymousLabel(uintptr_t fromAddress) {
	uintptr_t result = 0;
	for (uintptr_t addr : m_anonymousLabels) {
		if (addr < fromAddress) {
			result = addr;
		}
		else {
			break;
		}
	}
	return result;
}

uintptr_t CEAssemblyEngine::FindNextLabel(uintptr_t fromAddress) {
	// Find the next label after fromAddress using the ordered map
	for (const auto& [addr, name] : m_allLabels) {
		if (addr > fromAddress) {
			LOG_TRACE_F("Found next label '%s' at 0x%llX after 0x%llX",
				name.c_str(), addr, fromAddress);
			return addr;
		}
	}
	return 0;
}

uintptr_t CEAssemblyEngine::FindPreviousLabel(uintptr_t fromAddress) {
	uintptr_t result = 0;
	std::string resultName;

	// Find the previous label before fromAddress
	for (const auto& [addr, name] : m_allLabels) {
		if (addr < fromAddress) {
			result = addr;
			resultName = name;
		}
		else {
			break;  // Since map is ordered, we can stop here
		}
	}

	if (result != 0) {
		LOG_TRACE_F("Found previous label '%s' at 0x%llX before 0x%llX",
			resultName.c_str(), result, fromAddress);
	}

	return result;
}