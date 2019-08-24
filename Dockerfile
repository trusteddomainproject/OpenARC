# Use latest CentOS image
FROM centos:latest

# Build Arguments
ARG KEYFILE="none"
ARG DOMAIN="example.com"
ARG SELECTOR="example.com-domainkey"

# Set root password
RUN echo -e "openarctest\nopenarctest" | passwd

# Install SSH server
RUN yum install -y openssh-server monit

# SSH Configurations
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN ssh-keygen -A

# Install build dependencies
RUN yum -y install epel-release
RUN yum install -y git make automake rpm-build rpmdevtools libtool libbsd-devel openssl openssl-devel sendmail-milter sendmail-devel opendkim

# Change into root directory and create RPM Build Tree
RUN cd /root/ && rpmdev-setuptree

# Clone the repository
RUN git clone https://github.com/trusteddomainproject/OpenARC.git /root/OpenARC/

# Build the RPM
RUN cd /root/OpenARC/ \
    && autoreconf -fvi \
    && ./configure \
    && make \
    && make rpm

# Install openarc and libopenarc RPM packages
RUN  yum install -y $(find /root/rpmbuild/RPMS/x86_64/ -type f | grep -Ev "(devel|debug)")

# Create openarc configuration directory, generate example.com private key and TXT record
RUN mkdir -p /etc/openarc \
    && echo "Mode sv" >> /etc/openarc.conf \
    && echo "Keyfile is: ${KEYFILE}" \
    && /bin/sed -i \
                -e "s|#[ ]*Domain.*|Domain ${DOMAIN}|" \
                -e "s|#[ ]*Selector.*|Selector ${SELECTOR}|" \
                -e "s|#[ ]*KeyFile.*|KeyFile /etc/openarc/$(basename ${KEYFILE})|" \
                /etc/openarc.conf

# Copy KEYFILE onto the openarc key directory and make openarc own it
RUN echo "Copying ${KEYFILE} onto /etc/openarc/$(basename ${KEYFILE})"
COPY ${KEYFILE} /etc/openarc
RUN chown openarc:openarc -R /etc/openarc/ ; chmod 0600 /etc/openarc/$(basename ${KEYFILE})

# Expose SSHD and OpenARC default port
EXPOSE 22 8894

# Start SSHD
CMD /usr/sbin/sshd -p 22 ; openarc -c /etc/openarc.conf ; sleep infinity
