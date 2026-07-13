#!/usr/bin/env sh
set -eu
umask 077

if [ -n "${DOT_CERT_B64:-}" ]; then
  DOT_CERT_PEM=$(printf '%s' "$DOT_CERT_B64" | tr -d '\r\n ' | base64 -d)
  export DOT_CERT_PEM
fi

if [ -n "${DOT_KEY_B64:-}" ]; then
  DOT_KEY_PEM=$(printf '%s' "$DOT_KEY_B64" | tr -d '\r\n ' | base64 -d)
  export DOT_KEY_PEM
fi

normalize_pem_env() {
  variable_name="$1"
  eval "variable_value=\${$variable_name-}"
  if [ -n "$variable_value" ]; then
    variable_value=$(printf '%b' "$variable_value")
    export "$variable_name=$variable_value"
  fi
}

normalize_pem_env DOT_CERT_PEM
normalize_pem_env DOT_KEY_PEM

exec python /app/app/managed_main.py
