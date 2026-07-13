#!/usr/bin/env sh
set -eu
umask 077

decode_base64_env() {
  source_name="$1"
  target_name="$2"
  eval "source_value=\${$source_name-}"
  if [ -z "$source_value" ]; then
    return
  fi
  if ! decoded_value=$(printf '%s' "$source_value" | tr -d '\r\n ' | base64 -d); then
    echo "$source_name is not valid base64." >&2
    exit 1
  fi
  export "$target_name=$decoded_value"
}

normalize_pem_env() {
  variable_name="$1"
  eval "variable_value=\${$variable_name-}"
  if [ -n "$variable_value" ]; then
    variable_value=$(printf '%b' "$variable_value")
    export "$variable_name=$variable_value"
  fi
}

decode_base64_env DOT_CERT_B64 DOT_CERT_PEM
decode_base64_env DOT_KEY_B64 DOT_KEY_PEM
normalize_pem_env DOT_CERT_PEM
normalize_pem_env DOT_KEY_PEM

exec python /app/app/application.py
