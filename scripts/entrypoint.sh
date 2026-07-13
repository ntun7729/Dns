#!/usr/bin/env sh
set -eu
umask 077

normalize_pem_env() {
  variable_name="$1"
  eval "variable_value=\${$variable_name-}"
  if [ -n "$variable_value" ]; then
    # Render can preserve some real line breaks while leaving other separators
    # as the two visible characters \\n. Convert both forms before Python
    # writes the certificate and private key to disk.
    variable_value=$(printf '%b' "$variable_value")
    export "$variable_name=$variable_value"
  fi
}

normalize_pem_env DOT_CERT_PEM
normalize_pem_env DOT_KEY_PEM

exec python /app/app/main.py
