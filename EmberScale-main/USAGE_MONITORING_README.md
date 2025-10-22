# EmberScale Enhanced with Usage Monitoring

## Overview

EmberScale has been enhanced with comprehensive usage monitoring and cost tracking capabilities using the Anthropic Admin API. This provides detailed analytics, cost insights, and usage trends for your reverse engineering workflows.

## New Features

### 🔍 **Usage Monitoring**
- Real-time token usage tracking
- Model-specific usage analytics
- Service tier analysis
- Context window utilization tracking

### 💰 **Cost Tracking**
- Detailed cost breakdowns by model and service tier
- Daily, weekly, and monthly cost trends
- Cost analysis by workspace and operation type
- Budget monitoring and alerts

### 📊 **Analytics Dashboard**
- Comprehensive usage dashboard
- Interactive usage trends
- Cost analysis and projections
- API key management and monitoring

### 🛠️ **Enhanced Tool Integration**
- Automatic usage tracking for all EmberScale operations
- Local usage statistics
- Integration with existing QA Lite and RE Toolbox tools

## Setup Instructions

### 1. **API Key Configuration**

You'll need two types of API keys:

#### Regular API Key (Required)
- Used for normal EmberScale operations
- Set via environment variable: `ANTHROPIC_API_KEY`
- Or enter when prompted by the tools

#### Admin API Key (Optional, for full features)
- Required for usage monitoring and cost tracking
- Get from [Anthropic Console](https://console.anthropic.com/settings/admin-keys)
- Set via environment variable: `ANTHROPIC_ADMIN_API_KEY`
- Or use the enhanced setup wizard

### 2. **Installation**

1. **Copy the enhanced files to your Ghidra scripts directory:**
   ```
   EmberScale_Usage_Monitor.py
   decxy/admin_api.py
   ```

2. **Update existing scripts** (already done in this package):
   - `EmberScale_QA_Lite.py` - Enhanced with usage tracking
   - `EmberScale-RE_Toolbox.py` - Enhanced with usage tracking

### 3. **First-Time Setup**

Run the usage monitor to set up your API keys:

```python
# In Ghidra Script Manager, run:
EmberScale_Usage_Monitor.py
```

Choose "Setup Enhanced API Keys" to configure both regular and admin API keys.

## Usage Guide

### **Main Usage Monitor**

Run `EmberScale_Usage_Monitor.py` to access the enhanced features:

1. **Show Full Usage Dashboard** - Comprehensive analytics
2. **Usage Summary Only** - Token usage overview
3. **Cost Analysis Only** - Cost breakdown and trends
4. **API Key Information** - Manage and monitor API keys
5. **Usage Trends** - Historical usage analysis
6. **Cost Trends** - Historical cost analysis
7. **Claude Code Usage Report** - Claude Code specific metrics

### **Enhanced Existing Tools**

The existing EmberScale tools now automatically track usage:

- **QA Lite**: Tracks each query operation
- **RE Toolbox**: Tracks analysis sessions
- **Ghidra Script**: Tracks batch operations

### **Local Usage Statistics**

Even without Admin API access, the tools track local usage:

- Operation counts
- Token usage estimates
- Tool usage patterns
- Session statistics

## API Endpoints Used

### **Usage Reports**
- `/v1/organizations/usage_report/messages` - Messages API usage
- `/v1/organizations/usage_report/claude_code` - Claude Code usage

### **Cost Reports**
- `/v1/organizations/cost_report` - Cost analysis and billing

### **API Key Management**
- `/v1/organizations/api_keys` - List and manage API keys
- `/v1/organizations/api_keys/{id}` - Get specific API key details

## Features by API Key Type

### **Regular API Key Only**
- ✅ Basic EmberScale functionality
- ✅ Local usage tracking
- ✅ Operation counting
- ❌ Cost analysis
- ❌ Detailed usage reports
- ❌ API key management

### **With Admin API Key**
- ✅ All basic features
- ✅ Comprehensive usage analytics
- ✅ Cost tracking and analysis
- ✅ API key management
- ✅ Usage trends and insights
- ✅ Claude Code usage tracking

## Example Usage

### **Basic Usage Tracking**
```python
# Automatic tracking in existing tools
# No additional code needed - just use the enhanced tools
```

### **Manual Usage Tracking**
```python
from decxy.admin_api import track_usage_for_operation

# Track a custom operation
track_usage_for_operation("Custom_Analysis", tokens_used=1500)
```

### **Get Local Statistics**
```python
from EmberScale_Usage_Monitor import get_local_usage_stats
print(get_local_usage_stats())
```

## Cost Optimization Tips

### **Monitor High-Cost Operations**
- Use the cost dashboard to identify expensive operations
- Switch to more cost-effective models when appropriate
- Monitor context window usage

### **Usage Patterns**
- Track which tools are used most frequently
- Optimize prompts for better efficiency
- Use caching when possible

### **Budget Management**
- Set up regular cost monitoring
- Use daily/weekly cost reports
- Track cost trends over time

## Troubleshooting

### **Admin API Key Issues**
- Ensure you have Admin API key permissions
- Check that the key is correctly set in preferences
- Verify the key is active in Anthropic Console

### **Usage Tracking Not Working**
- Check that `decxy/admin_api.py` is in the correct location
- Verify import statements in enhanced scripts
- Check Ghidra console for error messages

### **Cost Data Not Available**
- Admin API key required for cost tracking
- Some cost data may have delays
- Check API key permissions for billing access

## Security Considerations

### **API Key Storage**
- Keys are stored in Ghidra preferences (encrypted)
- Never commit API keys to version control
- Use environment variables in production

### **Data Privacy**
- Usage data is processed locally when possible
- Admin API calls are made only when needed
- No sensitive data is transmitted unnecessarily

## Advanced Features

### **Custom Analytics**
- Extend the admin API client for custom metrics
- Add custom tracking for specific operations
- Integrate with external analytics tools

### **Automated Reporting**
- Set up automated usage reports
- Create custom dashboards
- Integrate with monitoring systems

## Support and Updates

### **Getting Help**
- Check the Ghidra console for error messages
- Verify API key permissions in Anthropic Console
- Review the usage monitoring logs

### **Updates**
- Monitor for new Anthropic API features
- Update admin API client for new endpoints
- Enhance tracking capabilities as needed

## License and Attribution

This enhanced version maintains the original EmberScale license and adds usage monitoring capabilities using the Anthropic Admin API. All usage monitoring features are designed to work within Ghidra's security model and respect user privacy.

---

**Note**: Usage monitoring requires an Anthropic Admin API key with appropriate permissions. Some features may not be available depending on your account type and permissions.
