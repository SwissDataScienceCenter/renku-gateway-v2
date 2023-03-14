FROM golang:1.19.5-alpine3.17 as builder
WORKDIR /src
COPY . .
RUN apk add --no-cache make && \
    make build

FROM alpine:3.17
# NOTE: ARG parameters go out of scope after the build state they are defined in ends
ARG EXECUTABLE
USER 1000:1000
COPY --from=builder /src/build/${EXECUTABLE} /cmd
# NOTE: ARG parameters cannot be accessed in the entrypoint
ENTRYPOINT [ "/cmd" ]
