ARG OVS_VERSION=2.13.1
FROM ubuntu:20.04 as cni-binaries

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates

# Leading dot is required for the tar command below
ENV CNI_PLUGINS="./host-local ./loopback ./portmap"

RUN mkdir -p /opt/cni/bin && \
    wget -q -O - https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz | tar xz -C /opt/cni/bin $CNI_PLUGINS


FROM antrea/openvswitch:${OVS_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="Takes care of building the Antrea binaries as part of building the image."

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    ipset \
    jq \
 && rm -rf /var/lib/apt/lists/*

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
