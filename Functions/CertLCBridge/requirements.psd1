# This file enables modules to be automatically managed by the Functions service.
# See https://aka.ms/functionsmanageddependency for additional information.
#
# NOTE: DO NOT USE WITH FLEX FUNCTIONS - managed dependencies are not supported in the Flex Consumption plan.
# Keep the hashtable below empty and bundle the required modules with the function app instead.
#
# From the repository root, run these commands before publishing:
#
# Set-Location .\Functions\CertLCBridge
# Save-Module -Name Az.Accounts -RequiredVersion 5.5.3 -Path .\Modules -Repository PSGallery -Force
# Save-Module -Name Az.Automation -RequiredVersion 1.12.1 -Path .\Modules -Repository PSGallery -Force
#
# Save-Module downloads the pinned versions and their dependencies from PowerShell Gallery.
# The Modules folder is added to the function worker's PSModulePath and is included by
# "func azure functionapp publish <function-app-name>". No PowerShell-specific publish option is required
# because the project and target app declare the runtime. Downloaded module contents are ignored by Git;
# only Modules/.gitkeep is tracked, so repeat these commands for each fresh checkout before publishing.

@{
}