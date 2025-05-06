# Microsoft 365 BYOD Security Framework

A comprehensive framework and toolset for securing Bring Your Own Device (BYOD) environments in Microsoft 365.

## Overview

This repository provides guidance, tools, and resources for implementing robust security controls in Microsoft 365 environments that support BYOD scenarios. Our approach combines advanced E5 security capabilities with custom detection methods to protect corporate data across unmanaged devices.

## Key Components

### BYOD Security Architecture
- **Conditional Access Policies**: Risk-based access controls for unmanaged devices
- **Microsoft Intune MAM**: App protection without device enrollment 
- **Data Loss Prevention**: Preventing data exfiltration on personal devices
- **PowerShell Security**: Implementing Constrained Language Mode protections

### Advanced Threat Protection
- **Device Code Phishing Defense**: Mitigations against modern authentication attacks
- **Email Security**: KQL queries for targeted phishing detection
- **Red Team Defense**: Comprehensive coverage against sophisticated attack chains
- **Cross-Domain Detection**: Unified XDR monitoring across endpoints, email, and identity

### Microsoft Sentinel Integration
- **Custom Detections**: Advanced KQL queries for BYOD-specific threats
- **Automated Response**: Playbooks for common BYOD security incidents
- **Risk Monitoring**: Continuous assessment of unmanaged device risks

## Getting Started

1. Review the [E3 to E5 Migration Guide](./docs/M365E3toE5.md) for security capability planning
2. Implement [PowerShell Constrained Language Mode](./docs/PowerShell-Constrained-Language-Mode.md) on managed endpoints
3. Configure [Defender XDR Action Center](./docs/DefenderXDR-ActionCenter-Workshop.md) for automated response
4. Deploy [Red Team Defense](./docs/DefendingAgainstRedTeam.md) detection rules
```powershell
iex (irm "https://raw.githubusercontent.com/DataGuys/M365BYOD/refs/heads/main/deploy.ps1")
```
## KQL Queries

The repository includes production-ready KQL queries for:
- Phishing detection and investigation
- Identifying vulnerable user accounts
- Suspicious authentication monitoring
- Data exfiltration alerts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
