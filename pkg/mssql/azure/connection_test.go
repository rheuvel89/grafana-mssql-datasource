package azure

import (
	"testing"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name:        "relies on environment variables when nothing is configured",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{},
			settings:    &azsettings.AzureSettings{WorkloadIdentityEnabled: true},
			expected:    "fedauth=ActiveDirectoryWorkloadIdentity;",
		},
		{
			name:        "uses instance-wide settings",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{},
			settings: &azsettings.AzureSettings{
				WorkloadIdentityEnabled: true,
				WorkloadIdentitySettings: &azsettings.WorkloadIdentitySettings{
					ClientId:  "instance-client",
					TenantId:  "instance-tenant",
					TokenFile: "/var/run/secrets/azure/tokens/azure-identity-token",
				},
			},
			expected: "user id=instance-client@instance-tenant;tokenfilepath=/var/run/secrets/azure/tokens/azure-identity-token;fedauth=ActiveDirectoryWorkloadIdentity;",
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
					ClientId: "instance-client",
					TenantId: "instance-tenant",
				},
			},
			expected: "user id=ds-client@ds-tenant;fedauth=ActiveDirectoryWorkloadIdentity;",
		},
		{
			name:        "client ID without tenant ID",
			credentials: &azcredentials.AzureWorkloadIdentityCredentials{ClientId: "ds-client"},
			settings:    &azsettings.AzureSettings{WorkloadIdentityEnabled: true},
			expected:    "user id=ds-client;fedauth=ActiveDirectoryWorkloadIdentity;",
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
