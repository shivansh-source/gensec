FROM golang:1.24-alpine AS builder
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o gensec cmd/gensec/main.go

FROM alpine:latest

RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    curl \
    bash \
    gcc \
    musl-dev \
    ca-certificates

# Let pip install into system environment (PEP 668)
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# ✅ Semgrep from pip
RUN pip3 install semgrep

# ✅ Gitleaks from GitHub release (Go binary)
ENV GITLEAKS_VERSION=8.18.4
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
 && chmod +x /usr/local/bin/gitleaks

# ✅ Trivy install script
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

COPY --from=builder /build/gensec /usr/local/bin/gensec
RUN chmod +x /usr/local/bin/gensec

WORKDIR /scan

# ENV GROQ_API_KEY=""
ENV USER_PLAN="pro"

ENTRYPOINT ["gensec"]
CMD ["scan"]
