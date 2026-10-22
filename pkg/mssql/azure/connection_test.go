package azure

import (
	"testing"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tokenFile = "/var/run/secrets/azure/tokens/azure-identity-token"

func TestGetAzureCredentialDSNFragment_WorkloadIdentity(t *testing.T) {
	tests := []struct {
		name        string
		credentials *azcredentials.AzureWorkloadIdentityCredentials
		settings    *azsettings.AzureSettings
		expected    string
		expectedErr string
	}{
		{
			name:        "returns error when workload identity is disabled",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{},
			settings:    &azsettings.AzureSettings{},
			expectedErr: "workload identity authentication is not enabled",
		},
		{
			name:        "returns error when client ID is not configured",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{},
			settings:    &azsettings.AzureSettings{WorkloadIdentityEnabled: true},
			expectedErr: "workload identity client ID is not configured, set workload_identity_client_id in the [azure] section of the Grafana configuration",
		},
		{
			name:        "returns error when tenant ID is not configured",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{ClientId: "ds-client"},
			settings: &azsettings.AzureSettings{
				WorkloadIdentityEnabled:  true,
				WorkloadIdentitySettings: &azsettings.WorkloadIdentitySettings{TokenFile: tokenFile},
			},
			expectedErr: "workload identity tenant ID is not configured, set workload_identity_tenant_id in the [azure] section of the Grafana configuration",
		},
		{
			name:        "returns error when token file is not configured",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{},
			settings: &azsettings.AzureSettings{
				WorkloadIdentityEnabled: true,
				WorkloadIdentitySettings: &azsettings.WorkloadIdentitySettings{
					ClientId: "instance-client",
					TenantId: "instance-tenant",
				},
			},
			expectedErr: "workload identity token file is not configured, set workload_identity_token_file in the [azure] section of the Grafana configuration",
		},
		{
			name:        "uses instance-wide settings",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{},
			settings: &azsettings.AzureSettings{
				WorkloadIdentityEnabled: true,
				WorkloadIdentitySettings: &azsettings.WorkloadIdentitySettings{
					ClientId:  "instance-client",
					TenantId:  "instance-tenant",
					TokenFile: tokenFile,
				},
			},
			expected: "user id=instance-client@instance-tenant;tokenfilepath=" + tokenFile + ";fedauth=ActiveDirectoryWorkloadIdentity;",
		},
		{
			name: "datasource client and tenant IDs override instance-wide settings",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{
				ClientId: "ds-client",
				TenantId: "ds-tenant",
			},
			settings: &azsettings.AzureSettings{
				WorkloadIdentityEnabled: true,
				WorkloadIdentitySettings: &azsettings.WorkloadIdentitySettings{
					ClientId:  "instance-client",
					TenantId:  "instance-tenant",
					TokenFile: tokenFile,
				},
			},
			expected: "user id=ds-client@ds-tenant;tokenfilepath=" + tokenFile + ";fedauth=ActiveDirectoryWorkloadIdentity;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn, err := GetAzureCredentialDSNFragment(tt.credentials, tt.settings, "")
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, dsn)
		})
	}
}
