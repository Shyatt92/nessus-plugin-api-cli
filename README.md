# nessus-plugin-api-cli
A CLI built for querying the plugins API exposed by Nessus Professional


Modes:
  1) Expression mode:
     --expr/-e '("Windows Server" AND 2016) AND NOT 2019'
  2) Direct plugin ID mode:
     --plugin-id/-p 298556,283466

Authentication:
  - CLI:
      --access-key / --secret-key
      or
      --token
  - Environment variables:
      nessus_access_key
      nessus_secret_key
      nessus_api_token

Outputs:
  --out / -o   Comma-separated output types: json,csv,txt (txt output is simply a list of CVE numbers)
  --filename/-f Single base filename used for all requested outputs
  -k / --insecure  Suppress TLS verification warnings

Examples:
  python fetch_matched_nessus_plugins.py \
    --plugin-id 298556,283466 \
    --access-key ACCESS --secret-key SECRET \
    --out json,csv,txt --filename results -k

  python fetch_matched_nessus_plugins.py \
    --expr 'KB5075999 OR KB5073722' \
    --token TOKEN \
    --out csv --filename results -k
