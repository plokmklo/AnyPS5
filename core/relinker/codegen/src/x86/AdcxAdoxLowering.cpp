#include <codegen/x86/AdcxAdoxLowering.hpp>
#include <codegen/CodegenException.hpp>
#include <algorithm>
#include <array>
#include <limits>

namespace Codegen {

namespace {

constexpr std::int32_t kFrameSize = 160;
constexpr std::uint8_t kStack = 4;
constexpr std::uint32_t kOwnAdcx = 0x1;
constexpr std::uint32_t kOwnAdox = 0x800;

bool _prefix(std::uint8_t value) {
    return value == 0x2E || value == 0x36 || value == 0x3E || value == 0x26 || value == 0x64 || value == 0x65 || value == 0x67;
}

void _append32(std::vector<std::uint8_t>& bytes, std::int32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        bytes.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) >> shift));
}

std::uint8_t _rex(bool wide, std::uint8_t reg, std::uint8_t rm) {
    return static_cast<std::uint8_t>(0x40 | (wide ? 8 : 0) | ((reg & 8) >> 1) | ((rm & 8) >> 3));
}

void _register(StubBodyBuilder& body, std::uint8_t opcode, bool wide, std::uint8_t reg, std::uint8_t rm) {
    const std::array bytes{_rex(wide, reg, rm), opcode, static_cast<std::uint8_t>(0xC0 | ((reg & 7) << 3) | (rm & 7))};
    body.Raw(bytes);
}

void _stack(StubBodyBuilder& body, std::uint8_t opcode, bool wide, std::uint8_t reg, std::int32_t displacement) {
    std::vector<std::uint8_t> bytes{_rex(wide, reg, kStack), opcode, static_cast<std::uint8_t>(0x84 | ((reg & 7) << 3)), 0x24};
    _append32(bytes, displacement);
    body.Raw(bytes);
}

std::uint8_t _scratch(const AdcxAdoxOperands& operands) {
    std::array<bool, 16> used{};
    used[kStack] = used[operands.Destination] = true;
    if (!operands.Memory) {
        used[operands.Source] = true;
    } else {
        const auto& memory = *operands.Memory;
        if (memory.Rm == 4) {
            const auto base = static_cast<std::uint8_t>((memory.Sib & 7) | ((memory.RexIndexBase & 1) << 3));
            const auto index = static_cast<std::uint8_t>(((memory.Sib >> 3) & 7) | ((memory.RexIndexBase & 2) << 2));
            if (memory.Mod != 0 || (memory.Sib & 7) != 5) used[base] = true;
            if (index != kStack) used[index] = true;
        } else if (!memory.RipRelative) {
            used[memory.Rm | ((memory.RexIndexBase & 1) << 3)] = true;
        }
    }
    for (const auto reg : {11, 10, 9, 8, 0, 1, 2, 3, 5, 6, 7, 12, 13, 14, 15})
        if (!used[reg]) return static_cast<std::uint8_t>(reg);
    throw CodegenException("ADCX/ADOX has no scratch register");
}

void _loadMemory(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch) {
    const auto& memory = *operands.Memory;
    auto displacement = static_cast<std::int64_t>(memory.Displacement);
    if (memory.StackBase) displacement += kFrameSize;
    const bool address32 = std::find(memory.Prefixes.begin(), memory.Prefixes.end(), 0x67) != memory.Prefixes.end();
    if (!address32 && displacement > std::numeric_limits<std::int32_t>::max())
        throw CodegenException("ADCX/ADOX stack displacement does not fit after spilling");
    const auto mod = memory.StackBase ? 2 : memory.Mod;
    auto bytes = memory.Prefixes;
    bytes.push_back(static_cast<std::uint8_t>(_rex(operands.Wide, scratch, 0) | memory.RexIndexBase));
    bytes.push_back(0x8B);
    bytes.push_back(static_cast<std::uint8_t>((mod << 6) | ((scratch & 7) << 3) | memory.Rm));
    if (memory.Rm == 4) bytes.push_back(memory.Sib);
    const auto offset = bytes.size();
    if (mod == 1) bytes.push_back(static_cast<std::uint8_t>(displacement));
    if (mod == 2 || (mod == 0 && (memory.RipRelative || (memory.Rm == 4 && (memory.Sib & 7) == 5))))
        _append32(bytes, static_cast<std::int32_t>(displacement));
    if (memory.RipRelative)
        body.RipRelative(bytes, offset, static_cast<std::int64_t>(memory.InstructionLength) + memory.Displacement);
    else
        body.Raw(bytes);
}

void _adcRegister(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch, bool carryChain) {
    _register(body, carryChain ? 0x11 : 0x01, operands.Wide, scratch, operands.Destination);
}

void _adcTempSlot(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch, bool carryChain) {
    std::vector<std::uint8_t> bytes{_rex(operands.Wide, scratch, kStack), static_cast<std::uint8_t>(carryChain ? 0x11 : 0x01),
        static_cast<std::uint8_t>(0x44 | ((scratch & 7) << 3)), 0x24, 0x10};
    body.Raw(bytes);
}

void _parkSource(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch) {
    _stack(body, 0x89, operands.Wide, scratch, 24);
}

void _recallSource(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch) {
    _stack(body, 0x8B, operands.Wide, scratch, 32);
}

void _setoScratch(StubBodyBuilder& body, std::uint8_t scratch) {
    if (scratch >= 8) {
        const std::array<std::uint8_t, 1> rexSeto{0x41};
        body.Raw(rexSeto);
    }
    const std::array<std::uint8_t, 3> seto{0x0F, 0x90, static_cast<std::uint8_t>(0xC0 | (scratch & 7))};
    body.Raw(seto);
    std::vector<std::uint8_t> movzx{static_cast<std::uint8_t>(scratch >= 8 ? 0x45 : 0x40), 0x0F, 0xB6,
        static_cast<std::uint8_t>(0xC0 | ((scratch & 7) << 3) | (scratch & 7))};
    if (scratch < 8) movzx[0] = 0x40;
    body.Raw(movzx);
}

void _negScratch(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch) {
    if (scratch >= 8) {
        const std::array<std::uint8_t, 1> rexNeg{0x41};
        body.Raw(rexNeg);
    }
    const std::array<std::uint8_t, 2> neg{0xF7, static_cast<std::uint8_t>(0xD8 | (scratch & 7))};
    body.Raw(neg);
}

void _maskAndCombine(StubBodyBuilder& body, const AdcxAdoxOperands& operands, std::uint8_t scratch) {
    const auto own = operands.Adox ? kOwnAdox : kOwnAdcx;
    const std::array<std::uint8_t, 1> flagsSave{0x9C};
    const std::array<std::uint8_t, 1> flagsRestore{0x9D};
    const std::array<std::uint8_t, 5> clearSavedAdcx{0x48, 0x83, 0x24, 0x24, 0x01};
    const std::array<std::uint8_t, 8> clearSavedAdox{0x48, 0x81, 0x24, 0x24, 0x00, 0x08, 0x00, 0x00};
    const std::array<std::uint8_t, 4> orSaved{static_cast<std::uint8_t>(0x48 | ((scratch & 8) >> 1)), 0x0B,
        static_cast<std::uint8_t>(((scratch & 7) << 3) | 4), 0x24};
    body.Raw(flagsSave);
    if (own == kOwnAdcx) {
        _stack(body, 0x8B, true, scratch, 8);
        _register(body, 0x83, true, 4, scratch);
        const std::array<std::uint8_t, 1> keepEverythingButCarry{0xFE};
        body.Raw(keepEverythingButCarry);
        body.Raw(clearSavedAdcx);
        body.Raw(orSaved);
    } else {
        const std::array<std::uint8_t, 12> clearSavedOverflow{0x48, 0x81, 0xA4, 0x24, 0x08, 0x00, 0x00, 0x00, 0xFF, 0xF7, 0xFF, 0xFF};
        _stack(body, 0x8B, true, scratch, 0);
        _register(body, 0x83, true, 4, scratch);
        const std::array<std::uint8_t, 1> keepEverythingButCarry{0x01};
        body.Raw(keepEverythingButCarry);
        const std::array<std::uint8_t, 4> shiftCarryToOverflow{static_cast<std::uint8_t>(0x48 | ((scratch & 8) >> 3)), 0xC1,
            static_cast<std::uint8_t>(0xE0 | (scratch & 7)), 0x0B};
        body.Raw(shiftCarryToOverflow);
        body.Raw(clearSavedOverflow);
        const std::array<std::uint8_t, 5> orSavedFlags{static_cast<std::uint8_t>(0x48 | ((scratch & 8) >> 1)), 0x0B,
            static_cast<std::uint8_t>(0x44 | ((scratch & 7) << 3)), 0x24, 0x08};
        body.Raw(orSavedFlags);
    }
    if (scratch >= 8) {
        const std::array<std::uint8_t, 1> rexPush{static_cast<std::uint8_t>(0x41 | ((scratch & 8) >> 3))};
        body.Raw(rexPush);
    }
    const std::array<std::uint8_t, 1> pushScratch{static_cast<std::uint8_t>(0x50 | (scratch & 7))};
    body.Raw(pushScratch);
    body.Raw(flagsRestore);
    _stack(body, 0x8B, true, scratch, 16);
    _stack(body, 0x8D, true, kStack, kFrameSize + 16);
}

}

std::optional<AdcxAdoxOperands> DecodeAdcxAdox(const std::uint8_t* data, const std::size_t length) {
    std::size_t vex = 0;
    while (vex < length && _prefix(data[vex])) ++vex;
    if (vex + 5 <= length && data[vex] == 0xC4) {
        if ((data[vex + 1] & 0x1F) != 2)
            return std::nullopt;
        const auto pp = data[vex + 2] & 3;
        if (pp != 1 && pp != 3)
            return std::nullopt;
        if ((data[vex + 2] & 4) != 0)
            throw CodegenException("ADCX/ADOX requires VEX.L=0");
        if (((data[vex + 2] >> 3) & 15) != 0)
            throw CodegenException("ADCX/ADOX must not use VEX.vvvv");
        const auto extensions = static_cast<std::uint8_t>(~data[vex + 1]);
        const auto modrm = data[vex + 4];
        AdcxAdoxOperands operands{
            static_cast<std::uint8_t>(((modrm >> 3) & 7) | ((extensions & 0x80) >> 4)),
            static_cast<std::uint8_t>((modrm & 7) | ((extensions & 0x20) >> 2)),
            (data[vex + 2] & 0x80) != 0, pp == 3, std::nullopt};
        if ((modrm >> 6) == 3) {
            if (vex + 5 != length) throw CodegenException("ADCX/ADOX register operand has trailing bytes");
        } else {
            const auto rex = static_cast<std::uint8_t>(((extensions & 0x20) >> 5) | ((extensions & 0x40) >> 5));
            operands.Memory = DecodeMemoryOperand(data, length, vex + 4, rex, {data, data + vex});
            if (vex + 4 + operands.Memory->EncodedSize != length)
                throw CodegenException("ADCX/ADOX memory operand has trailing bytes");
        }
        return operands;
    }
    std::size_t pos = 0;
    std::vector<std::uint8_t> prefixes;
    std::uint8_t rex = 0;
    bool operand66 = false;
    bool repF3 = false;
    while (pos < length) {
        const auto value = data[pos];
        if (value == 0x66 && !repF3 && rex == 0) {
            operand66 = true;
            ++pos;
        } else if (value == 0xF3 && !operand66 && rex == 0) {
            repF3 = true;
            ++pos;
        } else if (value >= 0x40 && value <= 0x4F && rex == 0) {
            rex = value;
            ++pos;
        } else if (_prefix(value)) {
            prefixes.push_back(value);
            ++pos;
        } else {
            break;
        }
    }
    if (operand66 == repF3)
        return std::nullopt;
    if (pos + 3 > length || data[pos] != 0x0F || data[pos + 1] != 0x38 || data[pos + 2] != 0xF6)
        return std::nullopt;
    const auto modrmOffset = pos + 3;
    if (modrmOffset >= length)
        return std::nullopt;
    const auto modrm = data[modrmOffset];
    AdcxAdoxOperands operands{
        static_cast<std::uint8_t>(((modrm >> 3) & 7) | ((rex & 4) << 1)),
        static_cast<std::uint8_t>((modrm & 7) | ((rex & 1) << 3)),
        (rex & 8) != 0, repF3, std::nullopt};
    if ((modrm >> 6) == 3) {
        if (modrmOffset + 1 != length) throw CodegenException("ADCX/ADOX register operand has trailing bytes");
    } else {
        operands.Memory = DecodeMemoryOperand(data, length, modrmOffset, static_cast<std::uint8_t>(rex & 3), prefixes);
        if (modrmOffset + operands.Memory->EncodedSize != length)
            throw CodegenException("ADCX/ADOX memory operand has trailing bytes");
    }
    return operands;
}

void EmitAdcxAdox(StubBodyBuilder& body, const AdcxAdoxOperands& operands) {
    const auto scratch = _scratch(operands);
    _stack(body, 0x8D, true, kStack, -kFrameSize);
    _stack(body, 0x89, true, scratch, 0);
    if (operands.Destination == kStack) {
        _stack(body, 0x8D, true, scratch, kFrameSize);
        _stack(body, 0x89, operands.Wide, scratch, 8);
    }
    if (!operands.Memory && operands.Source == kStack)
        _stack(body, 0x8D, operands.Wide, scratch, kFrameSize);
    else if (!operands.Memory)
        _register(body, 0x8B, operands.Wide, scratch, operands.Source);
    else
        _loadMemory(body, operands, scratch);
    if (operands.Adox) {
        _parkSource(body, operands, scratch);
        body.Raw(std::array<std::uint8_t, 1>{0x9C});
        _setoScratch(body, scratch);
        _negScratch(body, operands, scratch);
        _recallSource(body, operands, scratch);
        if (operands.Destination == kStack)
            _adcTempSlot(body, operands, scratch, true);
        else
            _adcRegister(body, operands, scratch, true);
    } else {
        body.Raw(std::array<std::uint8_t, 1>{0x9C});
        if (operands.Destination == kStack)
            _adcTempSlot(body, operands, scratch, true);
        else
            _adcRegister(body, operands, scratch, true);
    }
    _maskAndCombine(body, operands, scratch);
    if (operands.Destination == kStack)
        _stack(body, 0x8B, operands.Wide, kStack, 8 - kFrameSize);
}

}
