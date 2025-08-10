# PARSEC - Platform for Azure Response & Security Event Correlation

## Project Overview

This project demonstrates the implementation of a Security Information and Event Management (SIEM) system using Microsoft Azure Sentinel. The lab environment monitors and detects security events on a Windows virtual machine, showcasing real-world security monitoring capabilities in a controlled environment.

## Objectives

- Deploy and configure Azure Sentinel for security monitoring
- Set up log collection from Windows endpoints
- Create custom analytics rules for threat detection
- Implement automated incident response workflows
- Gain hands-on experience with cloud-native SIEM tools

## Architecture

```
┌─────────────────┐         ┌──────────────┐         ┌─────────────┐
│   Windows VM    │────────▶│ Azure Monitor│────────▶│Log Analytics│
│  (deadpoet-VM1) │  AMA    │    Agent     │         │  Workspace  │
└─────────────────┘         └──────────────┘         └─────────────┘
                                                            │
                                                            ▼
                                                    ┌─────────────┐
                                                    │   Sentinel  │
                                                    │   (SIEM)    │
                                                    └─────────────┘
                                                            │
                                                            ▼
                                                    ┌─────────────┐
                                                    │Alert Rules &│
                                                    │  Incidents  │
                                                    └─────────────┘
```

## Components

### 1. **Azure Virtual Machine**
- **Name**: deadpoet-VM1
- **Purpose**: Target system generating security events
- **Configuration**: RDP enabled (Port 3389)
- **Network**: Isolated virtual network (deadpoet-VM1-vnet)

### 2. **Log Analytics Workspace**
- **Name**: deadpoet-LogAnalytics
- **Region**: East US
- **Purpose**: Centralized log storage and analysis
- **Data Sources**: Windows Security Events

### 3. **Microsoft Sentinel**
- **Data Connector**: Windows Security Events via AMA
- **Collection**: All security events
- **Retention**: 30 days (default)

### 4. **Detection Rules**
- **Rule Name**: Successful Local Sign Ins
- **Logic**: Detects successful system account logins
- **Frequency**: Every 5 minutes
- **Lookback**: 5 minutes
- **Severity**: Medium

## Prerequisites

- Azure subscription (Free tier compatible)
- Basic understanding of:
  - Cloud computing concepts
  - Windows security events
  - Log analysis fundamentals
  - KQL (Kusto Query Language) basics

## Deployment Steps

### Step 1: Create Resource Group
```bash
- Name: deadSIEM_VMs
- Region: East US
```

### Step 2: Deploy Virtual Machine
1. Create Windows Server VM
2. Configure networking with public IP
3. Enable RDP access
4. Install Azure Monitor Agent

### Step 3: Configure Log Analytics
1. Create Log Analytics workspace
2. Connect to VM via AMA
3. Configure data collection rules
4. Verify log ingestion

### Step 4: Enable Microsoft Sentinel
1. Add Sentinel to workspace
2. Configure data connectors
3. Enable Windows Security Events connector
4. Validate data flow

### Step 5: Create Analytics Rules
1. Design KQL query for detection logic
2. Configure rule parameters
3. Set alert properties
4. Enable incident creation

## Key Queries

### Successful System Logins
```kusto
SecurityEvent
| where Activity contains "success" and Account contains "system"
| project TimeGenerated, Account, Computer, Activity, EventID
```

### Failed RDP Attempts
```kusto
SecurityEvent
| where EventID == 4625
| where IpAddress != "-"
| summarize FailedAttempts = count() by IpAddress, Computer
| where FailedAttempts > 5
```

### Privilege Escalation Detection
```kusto
SecurityEvent
| where EventID in (4672, 4673, 4674)
| where AccountType == "User"
| project TimeGenerated, Account, Computer, Activity, PrivilegeList
```

## Monitoring & Detection Capabilities

- ✅ Real-time security event monitoring
- ✅ Automated threat detection
- ✅ Incident creation and management
- ✅ Custom alert rules
- ✅ 5-minute detection frequency
- ✅ Centralized logging
- ✅ Scalable architecture

## Skills Demonstrated

- **Cloud Security**: Azure security services configuration
- **SIEM Implementation**: End-to-end deployment
- **Log Analysis**: KQL query development
- **Security Monitoring**: Event correlation and detection
- **Infrastructure as Code**: Azure resource deployment
- **Incident Response**: Alert and incident configuration

## Future Enhancements

- [ ] Add more data sources (Linux, Firewall logs)
- [ ] Implement threat intelligence feeds
- [ ] Create custom workbooks and dashboards
- [ ] Add automated response playbooks
- [ ] Integrate with SOAR capabilities
- [ ] Implement machine learning-based detections
- [ ] Add geographic visualization of attacks
- [ ] Configure multi-stage attack detection

## Lessons Learned

1. **Cost Optimization**: Free tier limitations require careful resource management
2. **Query Performance**: Efficient KQL queries are crucial for large datasets
3. **False Positives**: Rule tuning is essential to reduce noise
4. **Data Ingestion**: Proper data collection configuration impacts detection capabilities
5. **Incident Management**: Clear severity classification improves response times

## Contributing

Feel free to fork this project and adapt it for your own learning purposes. Suggestions for improvements are welcome!

## License

This project is for educational purposes. Please ensure compliance with Azure's terms of service and your organization's security policies.

## Author

**deadpoet**
- GitHub: [@deadpoet](https://github.com/yourusername)
- Created: July 17, 2025

## 🙏 Acknowledgments

- Microsoft Azure for the free tier resources
- The cybersecurity community for shared knowledge
- Azure Sentinel documentation and tutorials

---

**Note**: This is a learning environment. Never expose production systems unnecessarily or use weak credentials in real deployments.
