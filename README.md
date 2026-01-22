# pingora-waf


## Run

From the workspace root:

```bash
# Uses ./config.yaml by default
cargo run -p pingora-waf -- --config ./config.yaml
```


```bash
cargo run -p pingora-waf -- --config ./aegis/config.yaml
```


## Quick HTTPS test

```bash
curl -vk https://example.com:8443 --resolve example.com:8443:127.0.0.1
```
