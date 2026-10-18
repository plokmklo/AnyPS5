#ifndef CODEGEN_X86_ADCXADOXLOWERING_HPP
#define CODEGEN_X86_ADCXADOXLOWERING_HPP

#include <codegen/x86/StubBodyBuilder.hpp>
#include <optional>

namespace Codegen {

struct AdcxAdoxOperands {
    std::uint8_t Destination;
    std::uint8_t Source;
    bool Wide;
    bool Adox;
    std::optional<MemoryOperand> Memory;
};

[[nodiscard]] std::optional<AdcxAdoxOperands> DecodeAdcxAdox(const std::uint8_t* data, std::size_t length);
void EmitAdcxAdox(StubBodyBuilder& body, const AdcxAdoxOperands& operands);

}

#endif
