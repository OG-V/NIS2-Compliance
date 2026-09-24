# A plain Linux server administered over SSH. Its security posture comes
# entirely from the sshd_config mounted in by the active profile.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && useradd -m -s /bin/bash ops \
 && echo 'ops:ops-lab-only' | chpasswd \
 && echo 'root:root-lab-only' | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
