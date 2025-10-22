# EmberScale - Advanced AI-Powered Reverse Engineering Tool

[![GitHub](https://img.shields.io/badge/GitHub-EmberScale--Enhanced-blue?style=flat-square&logo=github)](https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![Ghidra](https://img.shields.io/badge/Ghidra-11.4.2+-orange?style=flat-square)](https://ghidra-sre.org)

## Overview

EmberScale is a comprehensive reverse engineering tool that integrates advanced AI capabilities with Ghidra for enhanced binary analysis, vulnerability assessment, and security research. The tool leverages Anthropic's Claude AI models and the latest Agent Skills API to provide specialized analysis workflows, automated document generation, and intelligent reverse engineering assistance.

**Repository**: [https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced](https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced)

## Key Features

### Core Capabilities
- **AI-Powered Analysis**: Advanced binary analysis using Claude AI models
- **Agent Skills Integration**: Specialized reverse engineering workflows with document generation
- **Enhanced Ghidra Integration**: Deep integration with Ghidra's scripting API
- **Usage Monitoring**: Comprehensive cost tracking and usage analytics
- **Custom Skills Support**: Create and integrate custom reverse engineering Skills

### Analysis Types
- **Malware Analysis**: Advanced malware detection and analysis
- **Firmware Analysis**: Comprehensive firmware security assessment
- **Vulnerability Assessment**: Automated vulnerability detection and risk assessment
- **Function Analysis**: Intelligent function analysis and classification
- **String Analysis**: Advanced string pattern recognition and analysis
- **Cross-Reference Analysis**: Comprehensive cross-reference analysis

### Document Generation
- **Technical Reports**: Detailed analysis reports (Word/PDF)
- **Analysis Spreadsheets**: Structured data analysis (Excel)
- **Executive Presentations**: High-level summaries (PowerPoint)
- **Specialized Reports**: IOC reports, vulnerability assessments, remediation guides

## Project Structure

```
EmberScale-Enhanced/
├── EmberScale_Ghidra.py              # Main Ghidra integration script
├── EmberScale_QA_Lite.py             # Quick analysis tool
├── EmberScale-RE_Toolbox.py          # Comprehensive analysis toolbox
├── EmberScale_Enhanced.py            # Enhanced version with advanced UI
├── EmberScale_Agent_Skills.py        # Agent Skills integration
├── EmberScale_Usage_Monitor.py       # Usage monitoring dashboard
├── decxy/                            # Core API modules
│   ├── api.py                        # Anthropic API integration
│   ├── admin_api.py                  # Admin API for usage monitoring
│   ├── config.py                     # Configuration management
│   ├── decompiler.py                 # Decompiler integration
│   ├── gui.py                        # GUI components
│   └── utils.py                      # Utility functions
├── examples/                         # Example implementations
│   ├── custom_re_skill/             # Custom reverse engineering Skill
│   └── agent_skills_example.py      # Agent Skills usage examples
├── README.md                         # This file
├── USAGE_MONITORING_README.md        # Usage monitoring documentation
├── AGENT_SKILLS_README.md           # Agent Skills documentation
└── ENHANCEMENT_SUMMARY.md           # Enhancement summary
```

## 🛠️ Installation & Setup

### Prerequisites
1. **Ghidra**: Version 11.4.2 or later
2. **Python**: Python 3.8+ (for Jython compatibility)
3. **Anthropic API Key**: Required for AI analysis capabilities
4. **Internet Connection**: Required for API calls

### Installation Steps

1. **Download EmberScale**
   ```bash
   git clone https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced.git
   cd EmberScale-Enhanced
   ```

2. **Configure Ghidra**
   - Copy the `decxy` folder to your Ghidra scripts directory
   - Copy the main EmberScale scripts to your Ghidra scripts directory
   - Ensure Jython is properly configured in Ghidra

3. **Configure API Keys**
   - Run any EmberScale script in Ghidra
   - Enter your Anthropic API key when prompted
   - The key will be saved in Ghidra Preferences for future use

4. **Verify Installation**
   - Open Ghidra and load a binary
   - Run `EmberScale_Ghidra.py` from the Script Manager
   - Verify the API key is configured correctly

## Quick Start

### Basic Analysis
1. **Load a Binary**: Open your target binary in Ghidra
2. **Run Analysis**: Execute `EmberScale_Ghidra.py` from the Script Manager
3. **Select Analysis Type**: Choose from available analysis options
4. **Review Results**: Examine the AI-generated analysis results

### Advanced Analysis with Agent Skills
1. **Run Enhanced Script**: Execute `EmberScale_Agent_Skills.py`
2. **Select Specialized Analysis**: Choose from malware, firmware, or vulnerability analysis
3. **Generate Documents**: Let the AI generate comprehensive reports
4. **Review Outputs**: Examine generated Word documents, Excel spreadsheets, and PowerPoint presentations

### Usage Monitoring
1. **Run Usage Monitor**: Execute `EmberScale_Usage_Monitor.py`
2. **View Analytics**: Check usage statistics, costs, and trends
3. **Manage API Keys**: Configure and monitor API key usage
4. **Export Reports**: Generate usage reports for analysis

## 📊 Usage Examples

### Malware Analysis
```python
# Advanced malware analysis with Agent Skills
def perform_malware_analysis():
    # Collect malware indicators
    indicators = collect_malware_indicators()
    
    # Create analysis prompt
    prompt = create_malware_analysis_prompt(indicators)
    
    # Use specialized Skills
    skills = [
        {"type": "anthropic", "skill_id": "docx", "version": "latest"},
        {"type": "anthropic", "skill_id": "xlsx", "version": "latest"},
        {"type": "anthropic", "skill_id": "pptx", "version": "latest"}
    ]
    
    # Perform analysis
    response = call_claude_with_skills(prompt, skills)
```

### Firmware Analysis
```python
# Comprehensive firmware analysis
def perform_firmware_analysis():
    # Collect firmware data
    firmware_data = collect_firmware_indicators()
    
    # Create analysis prompt
    prompt = create_firmware_analysis_prompt(firmware_data)
    
    # Use specialized Skills
    skills = [
        {"type": "anthropic", "skill_id": "docx", "version": "latest"},
        {"type": "anthropic", "skill_id": "xlsx", "version": "latest"},
        {"type": "anthropic", "skill_id": "pdf", "version": "latest"}
    ]
    
    # Perform analysis
    response = call_claude_with_skills(prompt, skills)
```

### Vulnerability Assessment
```python
# Comprehensive vulnerability assessment
def perform_vulnerability_assessment():
    # Collect vulnerability data
    vuln_data = collect_vulnerability_indicators()
    
    # Create assessment prompt
    prompt = create_vulnerability_assessment_prompt(vuln_data)
    
    # Use specialized Skills
    skills = [
        {"type": "anthropic", "skill_id": "docx", "version": "latest"},
        {"type": "anthropic", "skill_id": "xlsx", "version": "latest"},
        {"type": "anthropic", "skill_id": "pptx", "version": "latest"}
    ]
    
    # Perform assessment
    response = call_claude_with_skills(prompt, skills)
```

## Configuration

### API Key Management
- **Automatic Storage**: API keys are automatically stored in Ghidra Preferences
- **Secure Storage**: Keys are encrypted and stored securely
- **Multiple Keys**: Support for regular and admin API keys
- **Key Validation**: Automatic validation of API key format and permissions

### Analysis Settings
- **Model Selection**: Choose between Claude Sonnet and other available models
- **Analysis Depth**: Configure analysis depth and detail level
- **Output Format**: Select desired output formats and document types
- **Custom Skills**: Configure custom reverse engineering Skills

### Usage Monitoring
- **Cost Tracking**: Monitor API usage costs and trends
- **Usage Analytics**: Track token usage, model usage, and operation types
- **Budget Alerts**: Set up cost alerts and usage limits
- **Report Generation**: Generate detailed usage reports

## Advanced Features

### Agent Skills Integration
- **Pre-built Skills**: Access to Anthropic's pre-built Skills (Excel, PowerPoint, Word, PDF)
- **Custom Skills**: Create and integrate custom reverse engineering Skills
- **Multi-Skill Workflows**: Combine multiple Skills for comprehensive analysis
- **Document Generation**: Automated generation of technical reports and presentations

### Enhanced UI Integration
- **Smart Selections**: Intelligent selection management with visual feedback
- **Advanced Navigation**: Enhanced program navigation and analysis
- **Interactive Tables**: Specialized table displays for analysis results
- **Status Integration**: Real-time status updates and progress tracking

### Usage Analytics
- **Cost Analysis**: Detailed cost breakdown and trend analysis
- **Usage Patterns**: Analysis of usage patterns and optimization opportunities
- **Performance Metrics**: Track analysis performance and efficiency
- **Custom Reports**: Generate custom usage and cost reports

## Security & Privacy

### Data Protection
- **Local Processing**: Analysis data remains on your local system
- **Secure API Calls**: All API calls use HTTPS encryption
- **Key Security**: API keys are stored securely in Ghidra Preferences
- **No Data Retention**: No analysis data is retained by external services

### Access Control
- **API Key Management**: Secure API key storage and management
- **Usage Limits**: Configurable usage limits and cost controls
- **Audit Logging**: Comprehensive logging of all analysis activities
- **Permission Management**: Fine-grained control over analysis capabilities

## Documentation

### Core Documentation
- **README.md**: This comprehensive overview
- **USAGE_MONITORING_README.md**: Detailed usage monitoring guide
- **AGENT_SKILLS_README.md**: Agent Skills integration documentation
- **ENHANCEMENT_SUMMARY.md**: Complete enhancement summary

### Example Implementations
- **agent_skills_example.py**: Complete examples of Agent Skills usage
- **custom_re_skill/**: Example custom reverse engineering Skill
- **Usage Examples**: Comprehensive usage examples and tutorials

### API Reference
- **Anthropic API**: Integration with Anthropic's Claude API
- **Ghidra API**: Deep integration with Ghidra's scripting API
- **Agent Skills API**: Integration with Anthropic's Agent Skills API

## Contributing

### Development Setup
1. **Fork the Repository**: Create your own fork of the project
2. **Create Branch**: Create a feature branch for your changes
3. **Make Changes**: Implement your improvements or fixes
4. **Test Changes**: Ensure all changes work correctly
5. **Submit PR**: Submit a pull request with your changes

### Contribution Guidelines
- **Code Quality**: Follow Python best practices and coding standards
- **Documentation**: Update documentation for any new features
- **Testing**: Ensure all changes are thoroughly tested
- **Compatibility**: Maintain compatibility with existing functionality

### Areas for Contribution
- **Custom Skills**: Develop new reverse engineering Skills
- **Analysis Algorithms**: Improve analysis accuracy and performance
- **UI Enhancements**: Improve user interface and experience
- **Documentation**: Improve documentation and examples
- **Testing**: Add comprehensive test coverage

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- **Ghidra Team**: For the excellent reverse engineering framework
- **Anthropic**: For the powerful Claude AI models and Agent Skills API
- **Community**: For feedback, contributions, and support

## Support

### Getting Help
- **Documentation**: Check the comprehensive documentation
- **Examples**: Review the example implementations
- **Community**: Join the community discussions
- **Issues**: Report issues and bugs

### Contact Information
- **GitHub Issues**: Report bugs and request features
- **Community Forum**: Join community discussions
- **Email Support**: Contact the development team
- **Documentation**: Check the comprehensive documentation

---

**EmberScale - Advanced AI-Powered Reverse Engineering Tool**

*Leveraging the power of AI to enhance reverse engineering workflows and security research.*

**Repository**: [https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced](https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced)
