# Image fast-dds-tpm
FROM debian:bookworm

# Install TSS and dependencies
RUN apt-get -q update \
    && apt-get install -y tpm2-tools tpm2-openssl swtpm swtpm-tools man-db libtss2-dev \
    && apt-get install -y tmux nano cmake g++ python3-pip wget git libasio-dev libtinyxml2-dev libssl-dev

# Build prerequisites
RUN mkdir /Fast-DDS && cd /Fast-DDS \
    && git clone https://github.com/eProsima/foonathan_memory_vendor.git \
    && mkdir foonathan_memory_vendor-build && cd foonathan_memory_vendor-build \
    && cmake ../foonathan_memory_vendor -DCMAKE_INSTALL_PREFIX=/Fast-DDS/install -DBUILD_SHARED_LIBS=ON \
    && cmake --build . --target install \
    && cd /Fast-DDS \
    && git clone https://github.com/eProsima/Fast-CDR.git \
    && mkdir Fast-CDR-build && cd Fast-CDR-build \
    && cmake ../Fast-CDR -DCMAKE_INSTALL_PREFIX=/Fast-DDS/install \
    && cmake --build . --target install

# Add and build sources
ADD ./ /Fast-DDS/Fast-DDS/
RUN mkdir -p /Fast-DDS/Fast-DDS-build && cd /Fast-DDS/Fast-DDS-build \
    && cmake ../Fast-DDS -DSECURITY=ON -DCOMPILE_EXAMPLES=ON -DINSTALL_EXAMPLES=ON -DINTERNAL_DEBUG=ON -DCMAKE_INSTALL_PREFIX=/Fast-DDS/install \
    && cmake --build . --target install -j`nproc`
RUN echo 'export LD_LIBRARY_PATH=/Fast-DDS/install/lib/' >> ~/.bashrc

# TPM simulator configuration
# Comment out this section if you plan to use a platform TPM instead
RUN echo '#!/bin/bash\n\
  set -e\n\
  if [ -z "$(ls -A $1)" ]; then\n\
    swtpm_setup --tpmstate $1 --tpm2 --create-ek-cert --create-platform-cert\n\
  else\n\
    echo "TPM directory $1 is already initialized..."\n\
  fi\n\
  swtpm socket --tpmstate dir=$1 --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init,startup-clear &\
' >> /launch-simulator.sh
RUN chmod +x /launch-simulator.sh
RUN echo 'export TPM2TOOLS_TCTI="swtpm:port=2321"' >> ~/.bashrc
RUN echo 'export TPM2OPENSSL_TCTI="swtpm:port=2321"' >> ~/.bashrc
RUN echo '/launch-simulator.sh /tmp/mytpm' >> ~/.bashrc
VOLUME /tmp/mytpm
# End of TPM simulator configuration

WORKDIR /Fast-DDS
CMD /bin/bash