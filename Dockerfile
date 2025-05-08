##############################################################
# Dockerfile to build GoBGPSec container images
# Based on ubuntu 24.04
##############################################################

# First stage: Building srx-crypto-api and gobgpsrx
FROM ubuntu:24.04
RUN apt-get update && \
    apt-get install -y --no-install-recommends git libconfig-dev uthash-dev build-essential wget libssl-dev automake ca-certificates

# Setup build environment
RUN mkdir -p /usr/local/go/bin
WORKDIR /root

# clone and install srx-crypto-api
RUN git clone https://github.com/usnistgov/NIST-BGP-SRx.git && \
    cd NIST-BGP-SRx/srx-crypto-api && \
    ./configure --prefix=/usr/local CFLAGS="-O0 -g" && \
    make -j && \
    make all install && \
    make clean

# install go
RUN wget https://go.dev/dl/go1.23.5.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.23.5.linux-amd64.tar.gz && rm go1.23.5.linux-amd64.tar.gz
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# install gobgpsrx
ENV CGO_LDFLAGS="-L/usr/local/lib64/srx/ -Wl,-rpath -Wl,/usr/local/lib64/srx/" CGO_CFLAGS="-I/usr/local/include/srx/"
RUN git clone https://github.com/usnistgov/gobgpsrx.git && \
    cd gobgpsrx && \
    go build -o /usr/local/go/bin ./...


ENV PATH="$PATH:/usr/local/go/bin" LD_LIBRARY_PATH="/usr/local/lib64/srx"

# run gobgpd
EXPOSE 179
ENTRYPOINT ["gobgpd"]
CMD ["-p", "-f", "/etc/gobgpd.conf", "--log-level=debug"]




######### example to build & run ############################
# docker build -t < image name [:version] > .
# docker run --rm -it --name <container name> \
#   -v < path/to/config/gobgpd.conf:/etc/gobgpd.conf \
#   -v < path/to/keys:/var/lib/bgpsec-keys \
#    < iamge name >:version
