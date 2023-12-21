---
runme:
  id: 01HJ60YVJCXHPF9SE0JKJMH3GD
  version: v2.0
---

# Wedding

Backend for Wedding's Landing

```bash {"id":"01HJ60YVJB260Q9WMDFKVNWE6P"}
sudo docker build --tag wedding_api .
sudo docker run --restart=always -d -it --name wedding_api -p 8181:8181 wedding_api
```