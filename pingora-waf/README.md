# pingora-waf (Pingora 0.6.0)

- 默认端口：443
- mTLS：默认开启
- 多证书（SNI）：支持 `certs/server/sni/<servername>/cert.pem|key.pem`
- 规则热更新：默认 3 秒

## 快速开始

1) 启动 upstream（示例 8080）：
```bash
python3 -m http.server 8080
```

2) 启动本项目（需要绑定 443 权限）：
```bash
cargo run --release -- --config config.yaml
```

3) mTLS + SNI 测试：
```bash
curl -vk https://example.com/   --resolve example.com:443:127.0.0.1   --cert certs/client/client.crt --key certs/client/client.key   --cacert certs/ca/ca.crt
```

编辑 `rules.yaml`，3 秒内生效（日志提示 rules updated）。

## 目录结构

见工程根目录结构。


## Observability

- Prometheus: GET http://<host>:9100/metrics
- OpenTelemetry: set env `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317`



## HTTP 支持
默认同时监听：
- HTTP  : 0.0.0.0:80
- HTTPS : 0.0.0.0:443（mTLS + SNI）
可在 config.yaml 里用 http_listen / listen 修改。


wrk -t4 -c200 -d20s -H "Host: www.b.test" http://127.0.0.1:80/

python3 -m http.server 18082