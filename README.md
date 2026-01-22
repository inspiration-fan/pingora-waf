# pingora-waf


## Run

From the workspace root:

```bash
# Uses ./config.yaml by default
cargo run -p pingora-waf -- --config ./config.yaml
```



## Quick HTTP/S test

```bash
curl -vk https://www.example.com:8443 --resolve www.example.com:8443:127.0.0.1
```
