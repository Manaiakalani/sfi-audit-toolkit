// Insecure Key Vault: public network exposed, no network ACLs.
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-contoso-dev'
  location: resourceGroup().location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}
