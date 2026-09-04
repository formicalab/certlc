// Deploys the certificate vault, its private network access, and audit diagnostics.
targetScope = 'resourceGroup'

param location string
param keyVaultName string
param softDeleteRetentionInDays int
param logAnalyticsWorkspaceId string
param peSubnetId string
param privateDnsZoneId string
param tags object

// Certificate storage is private-only and uses Azure RBAC for data-plane authorization.
resource keyVault 'Microsoft.KeyVault/vaults@2026-02-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    softDeleteRetentionInDays: softDeleteRetentionInDays
    enablePurgeProtection: true
    enableRbacAuthorization: true
    publicNetworkAccess: 'Disabled'
  }
  tags: tags
}

// Keep the endpoint with the vault so the module completes only after private connectivity is ready.
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2025-07-01' = {
  name: 'pe-vault-${keyVaultName}'
  location: location
  properties: {
    subnet: {
      id: peSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'pls-${keyVaultName}'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
    customNetworkInterfaceName: 'nic-pe-${keyVaultName}'
  }
  tags: tags
}

resource privateEndpointDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-07-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

// Send vault audit and policy evaluation records to the shared workspace.
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-${keyVaultName}'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
      }
      {
        category: 'AzurePolicyEvaluationDetails'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// Expose only values required by dependent service modules.
output id string = keyVault.id
output name string = keyVault.name