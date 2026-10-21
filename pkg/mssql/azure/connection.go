package azure

import (
	"fmt"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
)

func GetAzureCredentialDSNFragment(azureCredentials azcredentials.AzureCredentials, azureSettings *azsettings.AzureSettings, userAssertion string) (string, error) {
	connStr := ""
	switch c := azureCredentials.(type) {
	case *azcredentials.AzureManagedIdentityCredentials:
		if azureSettings.ManagedIdentityClientId != "" {
			connStr += fmt.Sprintf("user id=%s;", azureSettings.ManagedIdentityClientId)
		}
		connStr += fmt.Sprintf("fedauth=%s;",
			"ActiveDirectoryManagedIdentity")
	case *azcredentials.AzureWorkloadIdentityCredentials:
		if !azureSettings.WorkloadIdentityEnabled {
			return "", fmt.Errorf("workload identity authentication is not enabled")
		}
		// Per-datasource client and tenant IDs take precedence over the instance-wide settings.
		// Any value left empty is resolved by the driver from the AZURE_CLIENT_ID, AZURE_TENANT_ID
		// and AZURE_FEDERATED_TOKEN_FILE environment variables injected by the workload identity webhook.
		clientId, tenantId, tokenFile := c.ClientId, c.TenantId, ""
		if wi := azureSettings.WorkloadIdentitySettings; wi != nil {
			if clientId == "" {
				clientId = wi.ClientId
			}
			if tenantId == "" {
				tenantId = wi.TenantId
			}
			tokenFile = wi.TokenFile
		}
		if clientId != "" {
			if tenantId != "" {
				connStr += fmt.Sprintf("user id=%s@%s;", clientId, tenantId)
			} else {
				connStr += fmt.Sprintf("user id=%s;", clientId)
			}
		}
		if tokenFile != "" {
			connStr += fmt.Sprintf("tokenfilepath=%s;", tokenFile)
		}
		connStr += fmt.Sprintf("fedauth=%s;", "ActiveDirectoryWorkloadIdentity")
	case *azcredentials.AzureClientSecretCredentials:
		// "password" is passed as an argument rather than embedded in the
		// format string to prevent "password=%s" from appearing in the
		// compiled binary, which triggers a false positive in Trufflehog
		// scans that run in CI.
		connStr += fmt.Sprintf("user id=%s@%s;%s=%s;fedauth=%s;",
			c.ClientId,
			c.TenantId,
			"password",
			c.ClientSecret,
			"ActiveDirectoryApplication",
		)
	case *azcredentials.AzureEntraPasswordCredentials:
		if azureSettings.AzureEntraPasswordCredentialsEnabled {
			connStr += fmt.Sprintf("user id=%s;%s=%s;applicationclientid=%s;fedauth=%s;",
				c.UserId,
				"password",
				c.Password,
				c.ClientId,
				"ActiveDirectoryPassword",
			)
		} else {
			return "", fmt.Errorf("azure entra password authentication is not enabled")
		}
	case *azcredentials.AadCurrentUserCredentials:
		if userAssertion == "" {
			return "", fmt.Errorf("user ID token is empty but required for current user authentication")
		}
		connStr += fmt.Sprintf("user id=%s;userassertion=%s;%s=%s;fedauth=%s;",
			azureSettings.UserIdentityTokenEndpoint.ClientId, userAssertion, "password", azureSettings.UserIdentityTokenEndpoint.ClientSecret, "ActiveDirectoryOnBehalfOf")
	default:
		return "", fmt.Errorf("unsupported azure authentication type")
	}
	return connStr, nil
}
