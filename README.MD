# Introduction

This is a dockerhub request proxy running on VPS, in case you can't access the official service directly.

# How to use

1. Install

```bash
pip3 install -r requirements.txt
```

2. Run

```bash
python3 dockerhub-proxy.py
```

3. Config your docker daemon
edit ```/etc/docker/daemon.json``` file, and add the following config
```bash
{
  "registry-mirrors": ["http://youip:18888"],
  "insecure-registries": ["youip:18888"]
}
```