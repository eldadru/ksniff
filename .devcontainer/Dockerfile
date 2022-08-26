FROM mcr.microsoft.com/vscode/devcontainers/base:debian

# Install kubectl.
ARG KUBECTL_VERSION=v1.25.0
RUN curl -SOL \
  https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/$(dpkg --print-architecture)/kubectl \
  && install kubectl /usr/local/bin \
  && rm kubectl
