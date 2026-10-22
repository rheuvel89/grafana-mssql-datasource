import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AzureCredentialsForm, type Props } from './AzureCredentialsForm';

const defaultProps: Props = {
  managedIdentityEnabled: false,
  workloadIdentityEnabled: false,
  azureEntraPasswordCredentialsEnabled: false,
  userIdentityEnabled: false,
  credentials: { authType: 'clientsecret' },
  onCredentialsChange: jest.fn(),
};

describe('AzureCredentialsForm', () => {
  it('does not offer workload identity when it is disabled in Grafana config', async () => {
    render(<AzureCredentialsForm {...defaultProps} />);

    await userEvent.click(screen.getByRole('combobox'));

    expect(screen.queryByText('Workload Identity')).not.toBeInTheDocument();
  });

  it('offers workload identity when it is enabled in Grafana config', async () => {
    const onCredentialsChange = jest.fn();
    render(
      <AzureCredentialsForm {...defaultProps} workloadIdentityEnabled onCredentialsChange={onCredentialsChange} />
    );

    await userEvent.click(screen.getByRole('combobox'));
    await userEvent.click(screen.getByText('Workload Identity'));

    expect(onCredentialsChange).toHaveBeenCalledWith({ authType: 'workloadidentity' });
  });

  it('shows workload identity as the selected auth type and no client secret fields', () => {
    render(
      <AzureCredentialsForm {...defaultProps} workloadIdentityEnabled credentials={{ authType: 'workloadidentity' }} />
    );

    expect(screen.getByText('Workload Identity')).toBeInTheDocument();
    expect(screen.queryByLabelText('Tenant ID')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Client ID')).not.toBeInTheDocument();
    expect(screen.getByText('Configured in Grafana')).toBeInTheDocument();
  });
});
