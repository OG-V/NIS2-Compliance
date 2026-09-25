#!/bin/sh
# Configures the lab's Elasticsearch once it is up:
# - a least-privilege "nis2scan" user, as a client would create for the scanner;
# - log data whose retention depends on the profile:
#     weak:     an index managed by an ILM policy that deletes after 7 days
#               (not named logs-*-*: the built-in "logs" template claims those names
#               for data streams)
#     hardened: a data stream whose own lifecycle retains data for 180 days
set -eu
ES=http://search:9200
AUTH="elastic:${ELASTIC_PASSWORD}"

until curl -fsS -u "$AUTH" "$ES/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null; do
  sleep 2
done

call() {  # method path json
  curl -fsS -u "$AUTH" -X "$1" "$ES$2" -H 'Content-Type: application/json' -d "$3" >/dev/null
}

call PUT /_security/role/nis2scan \
  '{"cluster":["monitor","read_ilm"],"indices":[{"names":["*"],"privileges":["monitor","view_index_metadata"]}]}'
call PUT /_security/user/nis2scan "{\"password\":\"${ES_SCAN_PASSWORD}\",\"roles\":[\"nis2scan\"]}"

case "$LAB_PROFILE" in
  weak)
    call PUT /_ilm/policy/logs-7d \
      '{"policy":{"phases":{"hot":{"actions":{}},"delete":{"min_age":"7d","actions":{"delete":{}}}}}}'
    call PUT /app-logs-000001 '{"settings":{"index.lifecycle.name":"logs-7d"}}'
    call POST /app-logs-000001/_doc '{"@timestamp":"2026-09-26T00:00:00Z","message":"lab log line"}'
    ;;
  hardened)
    call PUT /_index_template/logs-nordmsp \
      '{"index_patterns":["logs-nordmsp*"],"data_stream":{},"priority":200,"template":{"lifecycle":{"data_retention":"180d"}}}'
    call POST /logs-nordmsp/_doc '{"@timestamp":"2026-09-26T00:00:00Z","message":"lab log line"}'
    ;;
esac
echo "search configured for the $LAB_PROFILE profile"
