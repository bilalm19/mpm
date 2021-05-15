ARG WORKSPACE=/go/src/mpm

FROM golang:1.13.0 as devel

RUN apt update && apt install -y build-essential

ARG WORKSPACE

WORKDIR ${WORKSPACE}

COPY . ./

RUN make test && make build

FROM alpine:3.12.0 as prod

ARG WORKSPACE

COPY --from=devel ${WORKSPACE}/mpmserver ./mpmserver

EXPOSE 2000

ENTRYPOINT ["./mpmserver"]
