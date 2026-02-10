{{- with secret "pki/issue/test-cert" "common_name=monitored.example.com" "ttl=24h" -}}
{{ .Data.certificate }}
{{ .Data.issuing_ca }}
{{- end -}}
