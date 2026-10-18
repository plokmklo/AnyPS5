#include <codegen/x86/AdcxAdoxLowering.hpp>
#include <codegen/x86/IAmd64OnlyInstructionMatcher.hpp>
#include <codegen/CodegenException.hpp>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>
#if (defined(__linux__) || defined(__APPLE__)) && defined(__x86_64__)
#include <sys/mman.h>
#endif

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint64_t kSentinel = 0xBADC0FFEE0DDF00Dull;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Bytes vexInstruction(bool wide, bool adox, std::uint8_t destination, std::uint8_t source) {
    return {0xC4, static_cast<std::uint8_t>(0xE2 ^ ((destination & 8) << 4) ^ ((source & 8) << 2)),
        static_cast<std::uint8_t>((wide ? 0x80 : 0) | (adox ? 3 : 1)),
        0xF6, static_cast<std::uint8_t>(0xC0 | ((destination & 7) << 3) | (source & 7))};
}

Bytes legacyInstruction(bool wide, bool adox, std::uint8_t destination, std::uint8_t source) {
    const auto rex = static_cast<std::uint8_t>((wide ? 8 : 0) | ((destination & 8) >> 1) | ((source & 8) >> 3));
    Bytes bytes{static_cast<std::uint8_t>(adox ? 0xF3 : 0x66)};
    if (rex != 0) bytes.push_back(static_cast<std::uint8_t>(0x40 | rex));
    bytes.insert(bytes.end(), {0x0F, 0x38, 0xF6});
    bytes.push_back(static_cast<std::uint8_t>(0xC0 | ((destination & 7) << 3) | (source & 7)));
    return bytes;
}

Bytes legacyMemoryInstruction(bool adox, std::uint8_t destination, std::uint8_t base) {
    const auto rex = static_cast<std::uint8_t>(8 | ((destination & 8) >> 1) | ((base & 8) >> 3));
    Bytes bytes{static_cast<std::uint8_t>(adox ? 0xF3 : 0x66), static_cast<std::uint8_t>(0x40 | rex)};
    bytes.insert(bytes.end(), {0x0F, 0x38, 0xF6});
    bytes.push_back(static_cast<std::uint8_t>(((destination & 7) << 3) | (base & 7)));
    return bytes;
}

void decoding() {
    for (bool wide : {false, true}) {
        for (bool adox : {false, true}) {
            for (std::uint8_t destination = 0; destination < 16; ++destination) {
                for (std::uint8_t source = 0; source < 16; ++source) {
                    const auto vexBytes = vexInstruction(wide, adox, destination, source);
                    const auto legacyBytes = legacyInstruction(wide, adox, destination, source);
                    for (const auto* bytes : {&vexBytes, &legacyBytes}) {
                        const auto operands = Codegen::DecodeAdcxAdox(bytes->data(), bytes->size());
                        require(operands && operands->Wide == wide && operands->Adox == adox && operands->Destination == destination && operands->Source == source && !operands->Memory, "ADCX/ADOX register decoding changed an operand");
                    }
                }
            }
        }
    }
    const auto memory = legacyMemoryInstruction(false, 0, 3);
    const auto operands = Codegen::DecodeAdcxAdox(memory.data(), memory.size());
    require(operands && operands->Wide && !operands->Adox && operands->Destination == 0 && operands->Memory && operands->Memory->Rm == 3, "ADCX memory operand was lost");
    const Bytes adoXsib{0xF3, 0x0F, 0x38, 0xF6, 0x04, 0xDE};
    const auto adoxOperands = Codegen::DecodeAdcxAdox(adoXsib.data(), adoXsib.size());
    require(adoxOperands && adoxOperands->Adox && !adoxOperands->Wide && adoxOperands->Destination == 0 && adoxOperands->Memory && adoxOperands->Memory->Rm == 4 && adoxOperands->Memory->Sib == 0xDE, "ADOX SIB operand was lost");
    for (const Bytes bytes : {Bytes{0x90}, Bytes{0x66, 0x0F, 0x38}, Bytes{0x66, 0x0F, 0x38, 0xF6}, Bytes{0x0F, 0x38, 0xF6, 0xC0}, Bytes{0x66, 0x0F, 0x38, 0xF7, 0xC0}, Bytes{0x66, 0xF3, 0x0F, 0x38, 0xF6, 0xC0}})
        require(!Codegen::DecodeAdcxAdox(bytes.data(), bytes.size()), "Unrelated or truncated opcode matched ADCX/ADOX");
    for (const Bytes bytes : {Bytes{0x66, 0x0F, 0x38, 0xF6, 0xC1, 0x90}, Bytes{0x66, 0x0F, 0x38, 0xF6, 0xC1, 0xC3}}) {
        bool rejected = false;
        try { (void)Codegen::DecodeAdcxAdox(bytes.data(), bytes.size()); }
        catch (const Codegen::CodegenException&) { rejected = true; }
        require(rejected, "ADCX/ADOX with trailing bytes was accepted");
    }
    const Bytes malformedVex{0xC4, 0xE2, 0xC1, 0xF6, 0xC0};
    bool rejected = false;
    try { (void)Codegen::DecodeAdcxAdox(malformedVex.data(), malformedVex.size()); }
    catch (const Codegen::CodegenException&) { rejected = true; }
    require(rejected, "VEX.vvvv use was silently accepted");
    const Bytes levelVex{0xC4, 0xE2, 0x85, 0xF6, 0xC0};
    rejected = false;
    try { (void)Codegen::DecodeAdcxAdox(levelVex.data(), levelVex.size()); }
    catch (const Codegen::CodegenException&) { rejected = true; }
    require(rejected, "VEX.L=1 was silently accepted");
}

void matching() {
    const auto bytes = vexInstruction(true, false, 0, 6);
    const auto intel = Codegen::MakeAmd64OnlyInstructionMatcher();
    const auto rosetta = Codegen::MakeAmd64OnlyInstructionMatcher(Codegen::Amd64OnlyTarget::Rosetta);
    require(!intel->Match(bytes.data(), bytes.size()), "Intel mode rewrote ADCX");
    const auto match = rosetta->Match(bytes.data(), bytes.size());
    require(match && match->InstructionName == "ADCX" && match->Lowering == Codegen::Amd64OnlyLowering::Trampoline && !match->Optional, "Rosetta mode did not require an ADCX trampoline");
    const auto legacy = legacyInstruction(true, true, 1, 6);
    const auto adoxMatch = rosetta->Match(legacy.data(), legacy.size());
    require(adoxMatch && adoxMatch->InstructionName == "ADOX", "Rosetta mode did not lower ADOX");
    const std::array<std::span<const std::uint8_t>, 2> sequence{bytes, legacy};
    require(rosetta->MatchSequence(sequence, {}).has_value(), "An ADCX/ADOX sequence could not move out of line");
}

struct State {
    std::array<std::uint64_t, 16> Input{};
    std::array<std::uint64_t, 16> Output{};
    std::uint64_t InputFlags = 0;
    std::uint64_t Flags = 0;
    std::array<std::uint64_t, 16> RedZone{};
    std::uint64_t EntryRsp = 0;
};

#if (defined(__linux__) || defined(__APPLE__)) && defined(__x86_64__)

class Execution {
public:
    Execution(const Bytes& site, std::uint64_t memoryValue) {
        const auto operands = Codegen::DecodeAdcxAdox(site.data(), site.size());
        require(operands.has_value(), "Execution site was not ADCX/ADOX");
        push(0);
        for (const auto reg : {3, 5, 12, 13, 14, 15})
            push(static_cast<std::uint8_t>(reg));
        rspToCell(48);
        statePtrToCell(0);
        loadCellTo(0, 16);
        bytes.insert(bytes.end(), {0x48, 0x8D, 0xA4, 0x24});
        append32(-128);
        bytes.insert(bytes.end(), {0x48, 0xB8});
        append64(kSentinel);
        for (int slot = 0; slot < 16; ++slot)
            storeAtStack(0, slot * 8);
        loadCellTo(0, 16);
        push(0);
        bytes.push_back(0x9D);
        rspToCell(72);
        for (std::uint8_t reg = 15; reg >= 1 && reg < 16; --reg) {
            if (reg == 4 || reg == 7) continue;
            load(reg, reg * 8);
        }
        load(0, 0);
        load(7, 7 * 8);
        Codegen::StubBodyBuilder builder;
        Codegen::EmitAdcxAdox(builder, *operands);
        auto body = builder.Finish();
        require(body.Relocations.empty(), "Execution sites must not need relocations");
        bytes.insert(bytes.end(), body.Bytes.begin(), body.Bytes.begin() + static_cast<std::ptrdiff_t>(body.ReturnBranchOffset));
        rspToCell(24);
        rspFromCell(72);
        for (std::uint8_t reg = 0; reg < 16; ++reg) {
            if (reg == 4) continue;
            push(reg);
        }
        bytes.push_back(0x9C);
        statePtrFromCell(0);
        popToState(33 * 8);
        for (int reg = 15; reg >= 0; --reg) {
            if (reg == 4) continue;
            popToState((16 + reg) * 8);
        }
        loadCellTo(0, 24);
        store(0, 20 * 8);
        for (int slot = 0; slot < 16; ++slot) {
            stackLoad(0, slot * 8);
            store(0, (34 + slot) * 8);
        }
        rspFromCell(48);
        for (const auto reg : {15, 14, 13, 12, 5, 3})
            pop(static_cast<std::uint8_t>(reg));
        pop(0);
        bytes.push_back(0xC3);
        require(bytes.size() < 4096, "Execution wrapper exceeded its code page");
        code = static_cast<std::uint8_t*>(mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        require(code != MAP_FAILED, "Cannot allocate execution test pages");
        std::memcpy(code, bytes.data(), bytes.size());
        std::memcpy(code + 4096 + 8, &memoryValue, sizeof(memoryValue));
        require(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0, "Cannot make ADCX/ADOX test code executable");
    }

    ~Execution() { if (code != MAP_FAILED) munmap(code, 8192); }

    void Run(State& state) const {
        std::memcpy(code + 4096 + 16, &state.InputFlags, sizeof(state.InputFlags));
        reinterpret_cast<void (*)(State*)>(code)(&state);
        std::memcpy(&state.EntryRsp, code + 4096 + 72, sizeof(state.EntryRsp));
    }
    const void* Memory() const { return code + 4096 + 8; }

private:
    Bytes bytes;
    std::uint8_t* code = reinterpret_cast<std::uint8_t*>(MAP_FAILED);

    void append32(std::int32_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) >> shift));
    }
    void append64(std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8) bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void push(std::uint8_t reg) {
        if (reg >= 8) bytes.push_back(0x41);
        bytes.push_back(static_cast<std::uint8_t>(0x50 | (reg & 7)));
    }
    void pop(std::uint8_t reg) {
        if (reg >= 8) bytes.push_back(0x41);
        bytes.push_back(static_cast<std::uint8_t>(0x58 | (reg & 7)));
    }
    void load(std::uint8_t reg, int displacement) {
        bytes.push_back(static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1)));
        bytes.push_back(0x8B);
        bytes.push_back(static_cast<std::uint8_t>(0x80 | ((reg & 7) << 3) | 7));
        append32(displacement);
    }
    void store(std::uint8_t reg, int displacement) {
        bytes.push_back(static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1)));
        bytes.push_back(0x89);
        bytes.push_back(static_cast<std::uint8_t>(0x80 | ((reg & 7) << 3) | 7));
        append32(displacement);
    }
    void stackLoad(std::uint8_t reg, int displacement) {
        bytes.push_back(static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1)));
        bytes.push_back(0x8B);
        bytes.push_back(static_cast<std::uint8_t>(0x80 | ((reg & 7) << 3) | 4));
        bytes.push_back(0x24);
        append32(displacement);
    }
    void storeAtStack(std::uint8_t reg, int displacement) {
        bytes.push_back(static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1)));
        bytes.push_back(0x89);
        bytes.push_back(static_cast<std::uint8_t>(0x80 | ((reg & 7) << 3) | 4));
        bytes.push_back(0x24);
        append32(displacement);
    }
    void popToState(int displacement) {
        pop(0);
        store(0, displacement);
    }
    void rspToCell(int slot) {
        bytes.insert(bytes.end(), {0x48, 0x89, 0x25});
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
    void rspFromCell(int slot) {
        bytes.insert(bytes.end(), {0x48, 0x8B, 0x25});
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
    void statePtrToCell(int slot) {
        bytes.insert(bytes.end(), {0x48, 0x89, 0x3D});
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
    void statePtrFromCell(int slot) {
        bytes.insert(bytes.end(), {0x48, 0x8B, 0x3D});
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
    void loadCellTo(std::uint8_t reg, int slot) {
        bytes.push_back(static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1)));
        bytes.push_back(0x8B);
        bytes.push_back(static_cast<std::uint8_t>(0x05 | ((reg & 7) << 3)));
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
};

void check(const State& state, const Codegen::AdcxAdoxOperands& operands, std::uint64_t source) {
    const auto mask = operands.Wide ? ~std::uint64_t{0} : 0xFFFFFFFFull;
    const auto own = operands.Adox ? 0x800ull : 0x1ull;
    const auto flagIn = operands.Adox ? (state.InputFlags >> 11) & 1 : state.InputFlags & 1;
    const auto destinationIn = operands.Destination == 4 ? state.EntryRsp : state.Input[operands.Destination];
    const auto sourceIn = (!operands.Memory && operands.Source == 4) ? state.EntryRsp : source;
    const unsigned __int128 wide = ((unsigned __int128)(destinationIn & mask)) + (sourceIn & mask) + flagIn;
    const auto sum = static_cast<std::uint64_t>(wide);
    const auto expected = static_cast<std::uint64_t>(wide & mask);
    for (std::size_t reg = 0; reg < 16; ++reg) {
        require(reg == 4 || state.Output[reg] == (reg == operands.Destination ? expected : state.Input[reg]), "ADCX/ADOX changed a source/scratch register or produced an incorrect result");
    }
    const auto expectedFlags = (state.InputFlags & ~own) | ((wide >> (operands.Wide ? 64 : 32)) != 0 ? own : 0);
    require((state.Flags & 0x8D5) == (expectedFlags & 0x8D5), "ADCX/ADOX did not preserve its defined flag semantics");
    if (operands.Destination == 4)
        require(state.Output[4] == expected, "ADCX/ADOX did not write the guest stack pointer");
    for (const auto value : state.RedZone) require(value == kSentinel, "ADCX/ADOX overwrote the caller's red zone");
}

State initialState() {
    State state;
    for (std::size_t reg = 0; reg < 16; ++reg) state.Input[reg] = 0xABCD123456789000ull + reg * 0x1234567ull;
    state.Input[4] = 0;
    return state;
}

void execution() {
    const std::array<std::uint64_t, 4> flagImages{0x2, 0x8D7, 0x3, 0x802};
    const std::array<std::uint64_t, 3> valueVariants{0x123456789ABCDEFull, 0, ~std::uint64_t{0}};
    for (bool wide : {false, true}) {
        for (bool adox : {false, true}) {
            for (std::uint8_t destination = 0; destination < 16; ++destination) {
                for (const std::uint8_t source : {std::uint8_t{2}, std::uint8_t{13}, destination}) {
                    const auto site = vexInstruction(wide, adox, destination, source);
                    Execution executable(site, 0);
                    for (const auto flags : flagImages) {
                        for (const auto variant : valueVariants) {
                            auto state = initialState();
                            state.InputFlags = flags;
                            if (variant == 0) state.Input.fill(0);
                            if (variant == ~std::uint64_t{0}) state.Input.fill(~std::uint64_t{0});
                            state.Output.fill(kSentinel);
                            executable.Run(state);
                            check(state, *Codegen::DecodeAdcxAdox(site.data(), site.size()), state.Input[source]);
                        }
                    }
                }
            }
            const auto legacySite = legacyInstruction(wide, adox, 1, 6);
            Execution legacyExecutable(legacySite, 0);
            auto state = initialState();
            state.InputFlags = 0x8D7;
            state.Output.fill(kSentinel);
            legacyExecutable.Run(state);
            check(state, *Codegen::DecodeAdcxAdox(legacySite.data(), legacySite.size()), state.Input[6]);
            const auto memorySite = legacyMemoryInstruction(adox, 0, 3);
            Execution memoryExecutable(memorySite, 0xFEDCBA9876543210ull);
            auto memoryState = initialState();
            memoryState.InputFlags = 0x802;
            memoryState.Input[3] = reinterpret_cast<std::uint64_t>(memoryExecutable.Memory());
            memoryState.Output.fill(kSentinel);
            memoryExecutable.Run(memoryState);
            check(memoryState, *Codegen::DecodeAdcxAdox(memorySite.data(), memorySite.size()), 0xFEDCBA9876543210ull);
        }
    }
}
#else
void execution() { std::cout << "ADCX/ADOX execution checks require a Linux/macOS x86-64 build\n"; }
#endif

}

int main() {
    try {
        decoding();
        matching();
        execution();
        std::cout << "ADCX/ADOX lowering checks passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
