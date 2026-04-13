#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/fixtures/captures"
TMP_ROOT="$(mktemp -d /tmp/tls-real-captures.XXXXXX)"

mkdir -p "$OUT_DIR"

cleanup() {
  if [[ -n "${CLIENT_PID:-}" ]]; then
    kill "$CLIENT_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${CAP_PID:-}" ]]; then
    kill -INT "$CAP_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

wait_for_file() {
  local path="$1"
  local attempts="${2:-50}"
  local i
  for ((i=0; i<attempts; i++)); do
    [[ -f "$path" ]] && return 0
    sleep 0.1
  done
  return 1
}

start_capture() {
  local port="$1"
  local pcap="$2"
  tcpdump -i lo0 -U -w "$pcap" "tcp port $port" >/dev/null 2>&1 &
  CAP_PID=$!
  sleep 1
}

stop_capture() {
  if [[ -n "${CAP_PID:-}" ]]; then
    kill -INT "$CAP_PID" >/dev/null 2>&1 || true
    wait "$CAP_PID" 2>/dev/null || true
    unset CAP_PID
  fi
}

start_server() {
  local log="$1"
  shift
  openssl s_server "$@" >/dev/null 2>"$log" &
  SERVER_PID=$!
  sleep 1
}

stop_server() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
    unset SERVER_PID
  fi
}

run_client_bg() {
  local log="$1"
  shift
  openssl s_client "$@" >"$log" 2>&1 &
  CLIENT_PID=$!
}

stop_client() {
  if [[ -n "${CLIENT_PID:-}" ]]; then
    kill "$CLIENT_PID" >/dev/null 2>&1 || true
    wait "$CLIENT_PID" 2>/dev/null || true
    unset CLIENT_PID
  fi
}

gen_self_signed() {
  local cert="$1"
  local key="$2"
  local subject="$3"
  local sigalg="${4:-sha256}"
  openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$cert" "-$sigalg" -days 1 -nodes -subj "$subject" >/dev/null 2>&1
}

gen_ca() {
  local cert="$1"
  local key="$2"
  openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$cert" -sha256 -days 1 -nodes -subj "/CN=Test CA" >/dev/null 2>&1
}

sign_cert() {
  local csr="$1"
  local cert="$2"
  local ca_cert="$3"
  local ca_key="$4"
  openssl x509 -req -in "$csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial -out "$cert" -days 1 -sha256 >/dev/null 2>&1
}

capture_sni() {
  local dir="$TMP_ROOT/sni" port=4510
  mkdir -p "$dir"
  gen_self_signed "$dir/cert.pem" "$dir/key.pem" "/CN=example.com"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/cert.pem" -key "$dir/key.pem" -tls1_3 -ign_eof -quiet
  start_capture "$port" "$OUT_DIR/sni.pcap"
  printf '' | openssl s_client -connect "127.0.0.1:$port" -servername example.com -tls1_3 -CAfile "$dir/cert.pem" -verify_return_error >/dev/null 2>&1 || true
  sleep 1
  stop_capture
  stop_server
}

capture_hostname() {
  local dir="$TMP_ROOT/hostname" port=4511
  mkdir -p "$dir"
  gen_self_signed "$dir/cert.pem" "$dir/key.pem" "/CN=other.example.com"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/cert.pem" -key "$dir/key.pem" -tls1_3 -ign_eof -quiet
  start_capture "$port" "$OUT_DIR/hostname.pcap"
  printf '' | openssl s_client -connect "127.0.0.1:$port" -servername example.com -tls1_3 -CAfile "$dir/cert.pem" -verify_hostname example.com -verify_return_error >/dev/null 2>&1 || true
  sleep 1
  stop_capture
  stop_server
}

capture_mitm() {
  local dir="$TMP_ROOT/mitm" port=4512
  mkdir -p "$dir"
  gen_self_signed "$dir/cert.pem" "$dir/key.pem" "/CN=example.com"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/cert.pem" -key "$dir/key.pem" -tls1_3 -ign_eof -quiet
  start_capture "$port" "$OUT_DIR/mitm.pcap"
  printf '' | openssl s_client -connect "127.0.0.1:$port" -servername example.com -tls1_3 -verify 1 -verify_return_error >/dev/null 2>&1 || true
  sleep 1
  stop_capture
  stop_server
}

capture_client_auth_fail() {
  local dir="$TMP_ROOT/client-auth-fail" port=4513
  mkdir -p "$dir"
  gen_ca "$dir/ca.crt" "$dir/ca.key"
  openssl req -newkey rsa:2048 -keyout "$dir/server.key" -out "$dir/server.csr" -nodes -subj "/CN=example.com" >/dev/null 2>&1
  sign_cert "$dir/server.csr" "$dir/server.crt" "$dir/ca.crt" "$dir/ca.key"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/server.crt" -key "$dir/server.key" -CAfile "$dir/ca.crt" -Verify 1 -tls1_3 -ign_eof -quiet
  start_capture "$port" "$OUT_DIR/client-auth-fail.pcap"
  printf '' | openssl s_client -connect "127.0.0.1:$port" -servername example.com -tls1_3 -CAfile "$dir/ca.crt" >/dev/null 2>&1 || true
  sleep 1
  stop_capture
  stop_server
}

capture_mtls() {
  local dir="$TMP_ROOT/mtls" port=4514
  mkdir -p "$dir"
  gen_ca "$dir/ca.crt" "$dir/ca.key"
  openssl req -newkey rsa:2048 -keyout "$dir/server.key" -out "$dir/server.csr" -nodes -subj "/CN=example.com" >/dev/null 2>&1
  sign_cert "$dir/server.csr" "$dir/server.crt" "$dir/ca.crt" "$dir/ca.key"
  openssl req -newkey rsa:2048 -keyout "$dir/client.key" -out "$dir/client.csr" -nodes -subj "/CN=client.example.com" >/dev/null 2>&1
  sign_cert "$dir/client.csr" "$dir/client.crt" "$dir/ca.crt" "$dir/ca.key"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/server.crt" -key "$dir/server.key" -CAfile "$dir/ca.crt" -Verify 1 -tls1_3 -ign_eof -quiet
  start_capture "$port" "$OUT_DIR/mtls.pcap"
  printf '' | openssl s_client -connect "127.0.0.1:$port" -servername example.com -tls1_3 -CAfile "$dir/ca.crt" -cert "$dir/client.crt" -key "$dir/client.key" >/dev/null 2>&1 || true
  sleep 1
  stop_capture
  stop_server
}

capture_hrr() {
  local dir="$TMP_ROOT/hrr" port=4515
  mkdir -p "$dir"
  gen_self_signed "$dir/cert.pem" "$dir/key.pem" "/CN=example.com"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/cert.pem" -key "$dir/key.pem" -tls1_3 -groups P-256 -ign_eof -quiet
  start_capture "$port" "$OUT_DIR/hrr.pcap"
  printf '' | openssl s_client -connect "127.0.0.1:$port" -servername example.com -tls1_3 -groups X25519:P-256 -CAfile "$dir/cert.pem" -verify_return_error >/dev/null 2>&1 || true
  sleep 1
  stop_capture
  stop_server
}

capture_psk_resumption() {
  local dir="$TMP_ROOT/psk-resumption" port=4516
  mkdir -p "$dir"
  gen_self_signed "$dir/cert.pem" "$dir/key.pem" "/CN=example.com"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/cert.pem" -key "$dir/key.pem" -tls1_3 -num_tickets 2 -ign_eof -quiet

  run_client_bg "$dir/warmup.log" -connect "127.0.0.1:$port" -servername example.com -tls1_3 -sess_out "$dir/sess.pem" -ign_eof
  sleep 2
  stop_client
  wait_for_file "$dir/sess.pem"

  start_capture "$port" "$OUT_DIR/psk-resumption.pcap"
  run_client_bg "$dir/resume.log" -connect "127.0.0.1:$port" -servername example.com -tls1_3 -sess_in "$dir/sess.pem" -ign_eof
  sleep 2
  stop_client
  stop_capture
  stop_server
}

capture_zero_rtt() {
  local dir="$TMP_ROOT/zero-rtt" port=4517
  mkdir -p "$dir"
  gen_self_signed "$dir/cert.pem" "$dir/key.pem" "/CN=example.com"
  start_server "$dir/server.log" -accept "$port" -cert "$dir/cert.pem" -key "$dir/key.pem" -tls1_3 -num_tickets 2 -max_early_data 1024 -early_data -ign_eof -quiet

  run_client_bg "$dir/warmup.log" -connect "127.0.0.1:$port" -servername example.com -tls1_3 -sess_out "$dir/sess.pem" -ign_eof
  sleep 2
  stop_client
  wait_for_file "$dir/sess.pem"

  printf 'PING\n' > "$dir/early.txt"
  start_capture "$port" "$OUT_DIR/zero-rtt.pcap"
  run_client_bg "$dir/early.log" -connect "127.0.0.1:$port" -servername example.com -tls1_3 -sess_in "$dir/sess.pem" -early_data "$dir/early.txt" -ign_eof
  sleep 2
  stop_client
  stop_capture
  stop_server
}

capture_sni
capture_hostname
capture_mitm
capture_client_auth_fail
capture_mtls
capture_hrr
capture_psk_resumption
capture_zero_rtt

python3 "$ROOT/scripts/refresh_capture_manifest.py"
