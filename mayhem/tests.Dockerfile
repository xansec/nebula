FROM golang AS builder

COPY . /workspace
WORKDIR /workspace

RUN go test -c -o ./nebula_test

FROM ubuntu

COPY --from=builder /workspace/nebula_test /


