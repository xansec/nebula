FROM golang:1.22 as builder

RUN apt update && apt install -y clang

COPY . /nebula
WORKDIR /nebula/harnesses

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN go get github.com/AdaLogics/go-fuzz-headers
# WORKDIR /nebula/harnesses/firewall

# RUN go-fuzz-build \
#     -preserve crypto/internal/bigmod \
#     -libfuzzer \
#     -func FuzzAddFirewallRulesFromConfig \
#     -o fuzz_add_firewall_rules_from_config.a && \
#     clang \
#     -fsanitize=fuzzer \
#     fuzz_add_firewall_rules_from_config.a \
#     -o fuzz_add_firewall_rules_from_config.libfuzzer
# RUN go-fuzz-build \
#     -preserve crypto/internal/bigmod \
#     -libfuzzer \
#     -func FuzzFirewall_AddRule \
#     -o fuzz_firewall_add_rule.a && \
#     clang \
#     -fsanitize=fuzzer \
#     fuzz_firewall_add_rule.a \
#     -o fuzz_firewall_add_rule.libfuzzer
# RUN go-fuzz-build \
#     -preserve crypto/internal/bigmod \
#     -libfuzzer \
#     -func FuzzFirewallDrop \
#     -o fuzz_firewall_drop.a && \
#     clang \
#     -fsanitize=fuzzer \
#     fuzz_firewall_drop.a \
#     -o fuzz_firewall_drop.libfuzzer
# RUN go-fuzz-build \
#     -preserve crypto/internal/bigmod \
#     -libfuzzer \
#     -func FuzzNewFirewallFromConfig \
#     -o fuzz_new_firewall_from_config.a && \
#     clang \
#     -fsanitize=fuzzer \
#     fuzz_new_firewall_from_config.a \
#     -o fuzz_new_firewall_from_config.libfuzzer
# RUN go-fuzz-build \
#     -preserve crypto/internal/bigmod \
#     -libfuzzer \
#     -func FuzzNewFirewall \
#     -o fuzz_new_firewall.a && \
#     clang \
#     -fsanitize=fuzzer \
#     fuzz_new_firewall.a \
#     -o fuzz_new_firewall.libfuzzer

WORKDIR /nebula/harnesses/outside

RUN go-fuzz-build \
    -preserve crypto/internal/bigmod \
    -libfuzzer \
    -func FuzzNewPacket \
    -o fuzz_new_packet.a && \
    clang \
    -fsanitize=fuzzer \
    fuzz_new_packet.a \
    -o fuzz_new_packet.libfuzzer


FROM ubuntu
COPY --from=builder /nebula/harnesses/firewall/*.libfuzzer /nebula/harnesses/firewall/
COPY --from=builder /nebula/harnesses/outside/*.libfuzzer /nebula/harnesses/outside/


