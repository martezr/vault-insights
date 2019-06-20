path "sys/mounts"
{
  capabilities = ["read"]
}
path "sys/mounts/*"
{
  capabilities = ["list"]
}
path "secret/*" {
    capabilities = ["list"]
}
path "kv2secret/*" {
    capabilities = ["list"]
}
path "kv2secret/metadata/*"
{
  capabilities = ["read","list"]
}
