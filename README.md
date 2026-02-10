# 🛡️ Purple Team Operations Platform

Enterprise-grade Purple Team automation platform for penetration testing, threat detection, and security operations.

![Purple Team Platform](https://img.shields.io/badge/Purple%20Team-OPS-purple?style=for-the-badge)
![Next.js](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge)
![n8n](https://img.shields.io/badge/n8n-Workflows-orange?style=for-the-badge)
![Elastic](https://img.shields.io/badge/Elastic-SIEM-blue?style=for-the-badge)

## 🎯 Features

### Pentest Module
- **Credentialed Attacks**: Execute authenticated penetration tests with SSH credentials
- **Black Box Attacks**: Run unauthenticated Metasploit exploits against targets
- **Attack History**: Track all execution history with status indicators

### AI Analysis
- **Ingest & Report**: AI-generated attack reconstruction with MITRE ATT&CK mapping
- **Professional PDF Export**: Generate audit-ready security reports
- **Attack Timeline**: Chronological event reconstruction

### Remediation Engine
- **Three-Phase Remediation**: Immediate, short-term, and long-term steps
- **Human Approval Loop**: Approve or edit commands before execution
- **Direct Execution**: Run remediation commands via n8n SSH integration

### SIEM Integration
- **Detection Rules**: Auto-generated Elastic SIEM detection rules
- **Threat Intel Enrichment**: Enrich rules with MITRE ATT&CK context
- **One-Click Deploy**: Upload rules directly to Elastic SIEM

### Alert Monitoring
- **Real-Time Alerts**: Pull alerts from Elastic SIEM
- **Rule Performance**: Track which rules are triggering
- **Tuning Interface**: Submit tuning requests for noisy rules

### Threat Intelligence
- **Multi-Source Support**: AlienVault OTX, VirusTotal, MISP, custom APIs
- **Data Mapping**: Configure custom field mappings
- **Connection Testing**: Verify TI source connectivity

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Purple Team Platform (Next.js)               │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Pentest  │ │    AI    │ │  Threat  │ │  Alerts  │           │
│  │  Module  │ │ Analysis │ │  Intel   │ │ Monitor  │           │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
│       │            │            │            │                  │
│       └────────────┴────────────┴────────────┘                  │
│                         │                                       │
│                    Webhooks API                                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      n8n Workflows                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ SSH Execute  │  │ AI Analysis  │  │ Discord Bot  │          │
│  │   (Attack)   │  │   (LLM)      │  │  (Notify)    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│         └─────────────────┴─────────────────┘                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────────┐
        │  Target  │ │ Discord  │ │ Elastic SIEM │
        │ Systems  │ │ Channel  │ │              │
        └──────────┘ └──────────┘ └──────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- n8n instance (self-hosted or cloud)
- Discord bot token
- Elastic SIEM instance
- SSH access to target systems

### Installation

1. **Clone and install dependencies**:
```bash
cd purple-team-platform
npm install
```

2. **Configure environment variables**:
```bash
cp .env.example .env.local
```

Edit `.env.local`:
```env
NEXT_PUBLIC_N8N_URL=http://localhost:5678
NEXT_PUBLIC_PLATFORM_URL=http://localhost:3000
```

3. **Start the platform**:
```bash
npm run dev
```

4. **Import n8n workflows**:
   - Open n8n
   - Import `n8n-workflows/purple-team-main-workflow.json`
   - Import `n8n-workflows/discord-trigger-workflow.json`
   - Configure credentials (SSH, Discord, Elastic)

### n8n Configuration

#### Required Credentials

1. **SSH Credentials** (for target systems):
   - Name: `Target Server SSH`
   - Host, Username, Password

2. **Discord Bot**:
   - Name: `Purple Team Bot`
   - Bot Token

3. **Elastic API**:
   - Name: `Elastic SIEM`
   - URL, API Key

#### Environment Variables in n8n

Set these in n8n Settings → Variables:
- `PLATFORM_URL`: Your platform URL (e.g., `http://localhost:3000`)
- `ELASTIC_URL`: Your Elastic instance URL
- `DISCORD_CHANNEL_ID`: Target Discord channel

## 📖 Usage Guide

### Executing an Attack

1. Navigate to **Pentest** → **Black Box** or **Credentialed**
2. Configure target IP, port, and attack module
3. Click **Execute Attack**
4. Results appear in Discord and trigger AI analysis

### Reviewing AI Analysis

1. Navigate to **AI Analysis** → **Ingest & Report**
2. Select an analysis from the list
3. Review attack timeline, impact assessment
4. Export PDF report

### Applying Remediation

1. Navigate to **AI Analysis** → **Remediation**
2. Review remediation steps by phase
3. Edit commands if needed
4. Click **Approve & Execute** to run via SSH

### Deploying Detection Rules

1. Navigate to **AI Analysis** → **SIEM Rules**
2. Expand a rule to view details
3. Click **Enrich with TI** for threat intel context
4. Click **Apply to Elastic** to deploy

### Monitoring Alerts

1. Navigate to **Alerts**
2. Click **Refresh** to pull from Elastic
3. Filter by severity
4. Click **Tune** to submit tuning requests

## 🔧 API Endpoints

### Webhook Endpoints (for n8n)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/webhook/attack-result` | POST | Receive attack execution results |
| `/api/webhook/ai-analysis` | POST | Receive AI analysis results |
| `/api/webhook/notification` | POST | Receive platform notifications |

### n8n Webhook Paths

| Path | Description |
|------|-------------|
| `/webhook/pentest` | Trigger pentest execution |
| `/webhook/remediation` | Execute remediation command |
| `/webhook/elastic-rule` | Upload rule to Elastic |
| `/webhook/threat-intel` | Enrich with threat intel |
| `/webhook/fetch-alerts` | Fetch alerts from Elastic |

## 🎨 Customization

### Theming

Edit `tailwind.config.ts` to customize colors:

```typescript
colors: {
  'cyber-purple': '#a855f7',
  'neon-green': '#22c55e',
  // ... add your colors
}
```

### Adding Attack Modules

Edit `components/pages/PentestPage.tsx`:

```typescript
const attackModules = [
  { id: 'your_module', name: 'Module Name', description: 'CVE-XXX', port: '1234' },
  // ... add more modules
]
```

## 🔒 Security Considerations

⚠️ **Important Security Notes**:

1. **Credentials**: SSH and API credentials are stored in n8n, not the platform
2. **Network**: Ensure proper network segmentation between components
3. **Access Control**: Implement authentication before production use
4. **Logging**: All actions are logged for audit purposes
5. **Approval Loop**: Critical remediation requires human approval

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

**Built for Security Professionals** 🛡️

*Purple Team Operations Platform - Automate Your Security Workflow*

