FROM golang AS builder

COPY . /workspace
WORKDIR /workspace

RUN apt-get update -y && apt-get install -y make
RUN make bin

RUN ./nebula-cert ca -name "nebula"
RUN ./nebula-cert sign -name "lighthouse1" -ip "192.168.100.1/24"
RUN ./nebula-cert sign -name "host1" -ip "192.168.100.2/24"

FROM ubuntu

COPY --from=builder /workspace/nebula /workspace/mayhem/configs/*.yml /workspace/*.crt /workspace/*.key /
