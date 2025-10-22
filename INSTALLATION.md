# EmberScale Installation Guide

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 18.04+)
- **Java**: Java 11 or higher (required for Ghidra)
- **Python**: Python 3.8+ (for Jython compatibility)
- **Memory**: Minimum 8GB RAM (16GB recommended for large binaries)
- **Storage**: 2GB free space for Ghidra and EmberScale

### Required Software
- **Ghidra**: Version 11.4.2 or higher
- **Anthropic API Key**: Valid API key for Claude models

## Installation Steps

### 1. Install Ghidra

1. Download Ghidra from the [official website](https://ghidra-sre.org/)
2. Extract to your desired location (e.g., `C:\ghidra` on Windows)
3. Run Ghidra at least once to complete initial setup

### 2. Install EmberScale

#### Option A: Direct Installation
1. Download the latest EmberScale release
2. Extract to your Ghidra scripts directory:
   - **Windows**: `%USERPROFILE%\ghidra_scripts`
   - **macOS**: `~/ghidra_scripts`
   - **Linux**: `~/.ghidra/ghidra_scripts`

#### Option B: Git Clone
```bash
git clone https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced.git
cd EmberScale-Enhanced
```

### 3. Configure API Keys

#### Method 1: Environment Variables
```bash
# Windows
set ANTHROPIC_API_KEY=sk-ant-your-key-here

# macOS/Linux
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

#### Method 2: Ghidra Preferences
1. Open Ghidra
2. Go to `File > Configure > Preferences`
3. Navigate to `EmberScale` section
4. Enter your API key

#### Method 3: Interactive Setup
1. Run any EmberScale script
2. Follow the interactive setup prompts
3. API key will be saved automatically

### 4. Verify Installation

1. Open Ghidra
2. Load any binary file
3. Go to `Window > Script Manager`
4. Navigate to `EmberScale` folder
5. Run `EmberScale_Enhanced.py`
6. Verify the script loads without errors

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key | Required |
| `ANTHROPIC_MODEL` | Claude model to use | `claude-sonnet-4-20250514` |
| `EMBERSCALE_LOG_LEVEL` | Logging level | `INFO` |
| `EMBERSCALE_DEBUG` | Enable debug mode | `false` |

### Ghidra Preferences

Access via `File > Configure > Preferences > EmberScale`:

- **API Key**: Your Anthropic API key
- **Default Model**: Preferred Claude model
- **Analysis Depth**: Analysis detail level
- **Usage Tracking**: Enable/disable usage monitoring

## Troubleshooting

### Common Issues

#### 1. Script Not Appearing in Ghidra
- **Solution**: Ensure scripts are in the correct directory
- **Check**: Verify Ghidra scripts path in preferences

#### 2. API Key Not Working
- **Solution**: Verify API key format (`sk-ant-...`)
- **Check**: Test API key with Anthropic's API directly

#### 3. Import Errors
- **Solution**: Ensure all dependencies are installed
- **Check**: Verify Python/Jython installation

#### 4. Memory Issues
- **Solution**: Increase JVM heap size
- **Command**: `ghidraRun -J-Xmx8g` (adjust size as needed)

### Getting Help

1. **Check Logs**: Enable debug logging for detailed error information
2. **Documentation**: Review the comprehensive documentation
3. **Issues**: Report issues on GitHub
4. **Community**: Join discussions for support

## Advanced Configuration

### Custom Models
```python
# In your script
from decyx.config import CLAUDE_MODELS
print("Available models:", CLAUDE_MODELS)
```

### Custom Analysis Settings
```python
# Configure analysis parameters
MAX_FUNCTIONS = 100
ANALYSIS_DEPTH = "high"
ENABLE_DEBUG = True
```

### Usage Monitoring
```python
# Enable detailed usage tracking
ENABLE_USAGE_TRACKING = True
USAGE_TRACKING_INTERVAL = 300  # 5 minutes
```

## Security Considerations

### API Key Security
- Store API keys securely
- Use environment variables when possible
- Never commit API keys to version control
- Rotate keys regularly

### Network Security
- All API calls use HTTPS encryption
- No data is stored externally
- Analysis remains on your local system

### Privacy
- No analysis data is sent to external services
- Only prompts and responses are transmitted
- All data processing occurs locally

## Performance Optimization

### System Tuning
- **Memory**: Allocate sufficient RAM to Ghidra
- **CPU**: Use multi-core systems for better performance
- **Storage**: Use SSD for faster binary loading

### Analysis Optimization
- **Batch Processing**: Analyze multiple functions together
- **Selective Analysis**: Focus on specific code sections
- **Caching**: Enable result caching for repeated analyses

## Support and Maintenance

### Regular Updates
- Keep Ghidra updated to latest version
- Update EmberScale scripts regularly
- Monitor API key expiration

### Backup and Recovery
- Backup your Ghidra projects
- Export analysis results
- Maintain API key backups

---

**Need Help?** Check the [documentation](README.md) or [report an issue](https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced/issues).
