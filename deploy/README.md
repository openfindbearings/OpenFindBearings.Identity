# deploy（OpenFindBearings.Identity 部署模板）

本目录是认证中心 Identity 的 K8s 部署清单模板。部署时请将占位符替换为真实域名/网段/数据目录。

## 步骤

1. **创建 Secret**：`secrets/identity-secret-template.yml`（连接串 + OpenIddict 证书密码）与 **OpenIddict 证书 secret**（deployment 里 `openiddict-certs`，自行生成 `.pfx` 后建同名 Secret）
2. **替换占位符**：
   - `<your-identity-domain>`：Identity 域名（configMap.yml issuer、deploy.yml Ingress，TLS 由 cert-manager 签发）
   - `<your-site-domain>`：站点域名（configMap.yml AllowedOrigins）
   - `<your-pod-cidr>` / `<your-service-cidr>`：集群网段（deploy.yml，按自己集群实际值填）
   - `<your-data-dir>`：Data Protection 密钥持久目录的宿主机路径（deploy.yml hostPath，容器内 uid 1654 需有权限，见清单注释）
3. 镜像 `ghcr.io/openfindbearings/openfindbearings-identity`（公开）

## apply

```
secrets → configMap.yml → deploy.yml
```

> 完整运维清单（真实域名/密钥）在私有运维库，本目录只提供模板，占位符请在部署时替换为真实值。
