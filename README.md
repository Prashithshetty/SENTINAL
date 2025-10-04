# SENTINEL - AI-Powered Vulnerability Scanner

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.104.1-green" alt="FastAPI">
  <img src="https://img.shields.io/badge/AI-Gemini%202.0-purple" alt="Gemini AI">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</div>

## 🚀 Overview

SENTINEL is an advanced vulnerability scanner with integrated **Gemini 2.0 Flash AI** capabilities. It provides comprehensive security assessments with intelligent analysis, making vulnerability detection and remediation more effective than ever.

### ✨ Key Features

- **🤖 AI-Powered Analysis**: Integrated Gemini 2.0 Flash for intelligent vulnerability explanations
- **🔍 Comprehensive Scanning**: Multiple scanner modules for thorough security assessment
- **📊 Real-time Monitoring**: Live scan progress and results
- **🎯 Smart Prioritization**: AI-driven vulnerability prioritization
- **💡 Actionable Insights**: Detailed remediation recommendations
- **🌐 Modern Web Interface**: Responsive UI with real-time updates

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Gemini API key (get it free at [Google AI Studio](https://makersuite.google.com/app/apikey))

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SENTINEL.git
   cd SENTINEL
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ENABLE_INJECTION_TESTING=true
   ALLOW_ACTIVE_SCANNING=true
   DEBUG=false
   ```

4. **Start the backend server**
   ```bash
   python run_api.py
   ```

5. **Open the frontend**
   Open `frontend/index.html` in your browser

## 🎯 Usage

### Starting a Scan

1. Enter target URL or IP address
2. Select scan type (Passive, Active, or Aggressive)
3. Choose scanner modules
4. Click "Start Scan"
5. Monitor progress in real-time
6. View results with AI-powered analysis

### Available Scanner Modules

- **HTTP Scanner**: Web server analysis
- **DNS Enumeration**: Domain information gathering
- **SSL Scanner**: Certificate and encryption analysis
- **Content Discovery**: Hidden files and directories
- **XSS Scanner**: Cross-site scripting detection
- **SQL Injection**: Database vulnerability testing
- **Command Injection**: OS command injection detection
- **Network Scanner**: Port and service discovery
- **CVE Mapper**: Known vulnerability mapping
- **Info Disclosure**: Sensitive information exposure

### AI Features

- **Vulnerability Explanations**: Click "🤖 AI Explain" on any vulnerability
- **Full Scan Analysis**: Get comprehensive AI analysis of all findings
- **Risk Assessment**: AI-powered security posture evaluation
- **Remediation Guidance**: Step-by-step fixing instructions

## 📁 Project Structure

```
SENTINEL/
├── backend/
│   ├── api/              # FastAPI application
│   ├── core/             # Core functionality & AI integration
│   └── scanner/          # Scanner modules
├── frontend/
│   └── index.html        # Web interface with AI features
├── logs/                 # Application logs
├── reports/              # Scan reports
├── scan_results/         # Scan data storage
├── .env                  # Environment configuration
├── requirements.txt      # Python dependencies
└── run_api.py           # Server startup script
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Your Gemini API key | Required |
| `ENABLE_INJECTION_TESTING` | Allow injection tests | true |
| `ALLOW_ACTIVE_SCANNING` | Enable active scan mode | true |
| `DEBUG` | Debug mode | false |
| `REQUIRE_CONSENT` | Require scan consent | true |
| `MAX_CONCURRENT_SCANS` | Max parallel scans | 5 |
| `SCAN_TIMEOUT_SECONDS` | Scan timeout | 3600 |

## 🤝 API Endpoints

### Core Endpoints
- `GET /health` - API health check
- `GET /api/v1/modules` - List available modules
- `POST /api/v1/scans` - Start new scan
- `GET /api/v1/scans/{scan_id}` - Get scan status
- `GET /api/v1/scans/{scan_id}/results` - Get scan results

### AI Endpoints
- `POST /api/v1/scans/{scan_id}/analyze` - AI analysis of scan
- `POST /api/v1/vulnerabilities/{vuln_id}/explain` - AI explanation
- `POST /api/v1/security-suggestions` - Security recommendations

## 🔒 Security Considerations

- Always obtain proper authorization before scanning
- Use passive mode for initial assessments
- Review scan results carefully before taking action
- Keep your Gemini API key secure
- Regular updates recommended for latest security checks

## 📊 Performance

- Concurrent scanning support
- Asynchronous operations
- Rate limiting protection
- Efficient resource management
- Real-time progress updates

## 🐛 Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Check if backend server is running
   - Verify port 8000 is available

2. **AI Features Not Working**
   - Verify Gemini API key in `.env`
   - Check internet connection
   - Monitor API rate limits

3. **Scan Failures**
   - Check target accessibility
   - Verify network connectivity
   - Review module compatibility

## 🤖 AI Integration Details

SENTINEL uses **Gemini 2.0 Flash** to provide:

- **Intelligent Analysis**: Understanding vulnerability context
- **Risk Prioritization**: Focus on critical issues first
- **Custom Recommendations**: Tailored to your stack
- **Learning Insights**: Educational explanations
- **Compliance Guidance**: Regulatory requirement mapping

## 📈 Future Enhancements

- [ ] Additional scanner modules
- [ ] Enhanced reporting features
- [ ] CI/CD integration
- [ ] Cloud deployment options
- [ ] Advanced AI models
- [ ] Multi-language support

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Acknowledgments

- Powered by Google's Gemini 2.0 Flash AI
- Built with FastAPI and modern web technologies
- Community contributions and feedback

## 📧 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check documentation
- Review API documentation at `/docs` when server is running

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations.

**🚀 Ready to enhance your security posture with AI-powered vulnerability scanning!**
