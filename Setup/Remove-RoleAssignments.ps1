<#
.SYNOPSIS
    Removes all role assignments from resources in the rg-certlc-itn-001 resource group.

.DESCRIPTION
    This script safely removes all role assignments that are scoped to resources within
    the rg-certlc-itn-001 resource group. It does NOT remove assignments at the resource
    group level or subscription level - only those scoped to individual resources.

.PARAMETER ResourceGroupName
    The name of the resource group. Default: rg-certlc-itn-001

.PARAMETER SubscriptionId
    The subscription ID. Default: 4a570962-701a-475e-bf5b-8dc76ec748ff

.PARAMETER WhatIf
    If specified, shows what would be deleted without actually deleting.

.EXAMPLE
    .\Remove-RoleAssignments.ps1 -WhatIf
    Shows what would be deleted without actually deleting.

.EXAMPLE
    .\Remove-RoleAssignments.ps1
    Deletes all role assignments from resources in the resource group.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-certlc-itn-001",
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = "4a570962-701a-475e-bf5b-8dc76ec748ff"
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Role Assignment Cleanup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Subscription:   $SubscriptionId" -ForegroundColor Yellow
Write-Host ""

# Set the subscription context
Write-Host "Setting subscription context..." -ForegroundColor Green
az account set --subscription $SubscriptionId
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to set subscription context"
    exit 1
}

# Get all role assignments in the subscription
Write-Host "Fetching all role assignments..." -ForegroundColor Green
$allAssignments = az role assignment list --all --subscription $SubscriptionId | ConvertFrom-Json

if (-not $allAssignments) {
    Write-Host "No role assignments found in subscription." -ForegroundColor Yellow
    exit 0
}

# Filter for assignments scoped to resources in our resource group
$rgScopePattern = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/"
$targetAssignments = $allAssignments | Where-Object { 
    $_.scope -like "$rgScopePattern*" 
}

if ($targetAssignments.Count -eq 0) {
    Write-Host "No role assignments found scoped to resources in $ResourceGroupName." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Found $($targetAssignments.Count) role assignment(s) scoped to resources in $ResourceGroupName" -ForegroundColor Cyan
Write-Host ""

# Display what will be deleted
Write-Host "Role assignments to be removed:" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow
foreach ($assignment in $targetAssignments) {
    $resourceName = ($assignment.scope -split '/')[-1]
    $resourceType = (($assignment.scope -split '/providers/')[1] -split '/')[0..1] -join '/'
    
    Write-Host "  • Name:        $($assignment.name)" -ForegroundColor White
    Write-Host "    Role:        $($assignment.roleDefinitionName)" -ForegroundColor Gray
    Write-Host "    Description: $($assignment.description)" -ForegroundColor Gray
    Write-Host "    Resource:    $resourceName ($resourceType)" -ForegroundColor Gray
    Write-Host "    Scope:       $($assignment.scope)" -ForegroundColor DarkGray
    Write-Host ""
}

if ($WhatIfPreference) {
    Write-Host "WhatIf mode - no changes will be made." -ForegroundColor Magenta
    Write-Host ""
    exit 0
}

# Confirm before deletion
Write-Host ""
$confirmation = Read-Host "Do you want to delete these $($targetAssignments.Count) role assignment(s)? (yes/no)"
if ($confirmation -ne "yes") {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Deleting role assignments..." -ForegroundColor Green

$successCount = 0
$failCount = 0

foreach ($assignment in $targetAssignments) {
    try {
        Write-Host "  Deleting: $($assignment.name) ($($assignment.roleDefinitionName))..." -NoNewline
        
        az role assignment delete --ids $assignment.id 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " ✓" -ForegroundColor Green
            $successCount++
        }
        else {
            Write-Host " ✗" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host " ✗ Error: $_" -ForegroundColor Red
        $failCount++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Successfully deleted: $successCount" -ForegroundColor Green
Write-Host "  Failed:              $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($failCount -gt 0) {
    exit 1
}

Write-Host "Done! You can now redeploy your Bicep template." -ForegroundColor Green
