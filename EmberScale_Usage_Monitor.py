# -*- coding: utf-8 -*-
# EmberScale_Usage_Monitor.py
# @author Kevin Mitchell
# @category AI Analysis
# @toolbar
#
# Enhanced EmberScale with comprehensive usage monitoring and cost tracking.
# Integrates Anthropic Admin API for detailed analytics and reporting.
#
# Features:
# - Real-time usage monitoring
# - Cost tracking and analysis
# - API key management
# - Usage trends and insights
# - Claude Code usage tracking

import os
import json
from ghidra.framework.preferences import Preferences
from ghidra.util.task import ConsoleTaskMonitor
from decxy.admin_api import (
    show_usage_dashboard, generate_usage_summary, generate_cost_summary,
    get_api_key_info, get_usage_report, get_cost_report, get_claude_code_usage
)

# -------------------------
# Enhanced API Key Management
# -------------------------
def get_enhanced_api_key():
    """
    Enhanced API key management with usage monitoring integration.
    """
    prefs = Preferences.getUserPreferences()
    
    # Check for regular API key
    regular_key = prefs.getString("ANTHROPIC_API_KEY", None)
    if regular_key:
        print("✅ Regular API key found in preferences")
    
    # Check for Admin API key
    admin_key = prefs.getString("ANTHROPIC_ADMIN_API_KEY", None)
    if admin_key:
        print("✅ Admin API key found - usage monitoring enabled")
    else:
        print("⚠️  Admin API key not found - usage monitoring disabled")
        print("   Set ANTHROPIC_ADMIN_API_KEY for comprehensive analytics")
    
    return regular_key

def setup_enhanced_api_keys():
    """
    Setup both regular and admin API keys for full functionality.
    """
    print("=== EmberScale Enhanced API Key Setup ===")
    print("")
    
    # Regular API key for normal operations
    regular_key = get_enhanced_api_key()
    if not regular_key:
        print("Setting up regular API key...")
        try:
            entered = askString("Regular API Key", 
                              "Enter your regular Anthropic API key:", "")
            if entered and entered.strip():
                prefs = Preferences.getUserPreferences()
                prefs.putString("ANTHROPIC_API_KEY", entered.strip())
                prefs.flush()
                print("✅ Regular API key saved")
        except Exception:
            print("❌ Failed to save regular API key")
    
    # Admin API key for usage monitoring
    admin_key = os.environ.get("ANTHROPIC_ADMIN_API_KEY")
    if not admin_key:
        print("Setting up Admin API key for usage monitoring...")
        try:
            entered = askString("Admin API Key", 
                              "Enter your Anthropic Admin API key (optional, for usage monitoring):", "")
            if entered and entered.strip():
                prefs = Preferences.getUserPreferences()
                prefs.putString("ANTHROPIC_ADMIN_API_KEY", entered.strip())
                prefs.flush()
                print("✅ Admin API key saved - usage monitoring enabled")
        except Exception:
            print("⚠️  Admin API key not provided - usage monitoring disabled")

# -------------------------
# Usage Monitoring Menu
# -------------------------
def show_usage_menu():
    """
    Display usage monitoring menu with various options.
    """
    choices = [
        "Show Full Usage Dashboard",
        "Usage Summary Only",
        "Cost Analysis Only", 
        "API Key Information",
        "Usage Trends (Last 7 Days)",
        "Cost Trends (Last 7 Days)",
        "Claude Code Usage Report",
        "Setup Enhanced API Keys",
        "Exit"
    ]
    
    try:
        choice = askChoice("EmberScale Usage Monitor", 
                          "Select an option:", choices, choices[0])
    except Exception:
        choice = "Exit"
    
    if choice == "Show Full Usage Dashboard":
        show_usage_dashboard()
    
    elif choice == "Usage Summary Only":
        summary = generate_usage_summary()
        print(summary)
    
    elif choice == "Cost Analysis Only":
        cost_summary = generate_cost_summary()
        print(cost_summary)
    
    elif choice == "API Key Information":
        key_info = get_api_key_info()
        print(key_info)
    
    elif choice == "Usage Trends (Last 7 Days)":
        print("Fetching usage trends...")
        usage_data = get_usage_report()
        if usage_data:
            print("✅ Usage data retrieved successfully")
            print("Use 'Show Full Usage Dashboard' for detailed analysis")
        else:
            print("❌ Unable to fetch usage data")
    
    elif choice == "Cost Trends (Last 7 Days)":
        print("Fetching cost trends...")
        cost_data = get_cost_report()
        if cost_data:
            print("✅ Cost data retrieved successfully")
            print("Use 'Show Full Usage Dashboard' for detailed analysis")
        else:
            print("❌ Unable to fetch cost data")
    
    elif choice == "Claude Code Usage Report":
        print("Fetching Claude Code usage...")
        code_usage = get_claude_code_usage()
        if code_usage:
            print("✅ Claude Code usage data retrieved successfully")
            print("Use 'Show Full Usage Dashboard' for detailed analysis")
        else:
            print("❌ Unable to fetch Claude Code usage data")
    
    elif choice == "Setup Enhanced API Keys":
        setup_enhanced_api_keys()
    
    elif choice == "Exit":
        print("Exiting usage monitor...")

# -------------------------
# Enhanced Tool Integration
# -------------------------
def track_usage_for_operation(operation_name, tokens_used=None):
    """
    Track usage for a specific operation (can be called from other tools).
    
    Args:
        operation_name: Name of the operation being performed
        tokens_used: Optional token count for this operation
    """
    try:
        prefs = Preferences.getUserPreferences()
        
        # Get or create usage tracking data
        usage_data = prefs.getString("EMBERSCALE_USAGE_DATA", "{}")
        usage_dict = json.loads(usage_data) if usage_data else {}
        
        # Update operation count
        if operation_name not in usage_dict:
            usage_dict[operation_name] = {"count": 0, "total_tokens": 0}
        
        usage_dict[operation_name]["count"] += 1
        if tokens_used:
            usage_dict[operation_name]["total_tokens"] += tokens_used
        
        # Save updated data
        prefs.putString("EMBERSCALE_USAGE_DATA", json.dumps(usage_dict))
        prefs.flush()
        
        print("📊 Tracked operation: {} (Total: {})".format(
            operation_name, usage_dict[operation_name]["count"]))
        
    except Exception as e:
        print("⚠️  Usage tracking failed: {}".format(str(e)))

def get_local_usage_stats():
    """
    Get local usage statistics stored in preferences.
    """
    try:
        prefs = Preferences.getUserPreferences()
        usage_data = prefs.getString("EMBERSCALE_USAGE_DATA", "{}")
        usage_dict = json.loads(usage_data) if usage_data else {}
        
        if not usage_dict:
            return "No local usage data available."
        
        stats = []
        stats.append("=== Local Usage Statistics ===")
        stats.append("")
        
        total_operations = 0
        total_tokens = 0
        
        for operation, data in usage_dict.items():
            count = data.get("count", 0)
            tokens = data.get("total_tokens", 0)
            total_operations += count
            total_tokens += tokens
            
            stats.append("🔧 {}: {} operations, {} tokens".format(
                operation, count, tokens))
        
        stats.append("")
        stats.append("📊 Total: {} operations, {} tokens".format(
            total_operations, total_tokens))
        
        return "\n".join(stats)
        
    except Exception as e:
        return "Error retrieving local usage stats: {}".format(str(e))

# -------------------------
# Enhanced Main Function
# -------------------------
def main():
    """
    Enhanced main function with usage monitoring capabilities.
    """
    print("=== EmberScale Enhanced with Usage Monitoring ===")
    print("")
    
    # Check API key setup
    regular_key = get_enhanced_api_key()
    if not regular_key:
        print("❌ No API key found. Please run 'Setup Enhanced API Keys' first.")
        return
    
    # Show usage monitoring menu
    show_usage_menu()

# -------------------------
# Integration Functions
# -------------------------
def integrate_with_existing_tools():
    """
    Integration function to add usage monitoring to existing EmberScale tools.
    Call this from other EmberScale scripts to enable usage tracking.
    """
    print("🔗 Integrating usage monitoring with existing EmberScale tools...")
    
    # This function can be imported and called from other scripts
    # to add usage monitoring capabilities
    
    # Example: Track when QA Lite is used
    track_usage_for_operation("QA_Lite_Query")
    
    # Example: Track when RE Toolbox is used  
    track_usage_for_operation("RE_Toolbox_Analysis")
    
    print("✅ Usage monitoring integration complete")

def show_integration_status():
    """
    Show the status of usage monitoring integration.
    """
    print("=== EmberScale Usage Monitoring Status ===")
    print("")
    
    # Check API keys
    prefs = Preferences.getUserPreferences()
    regular_key = prefs.getString("ANTHROPIC_API_KEY", None)
    admin_key = prefs.getString("ANTHROPIC_ADMIN_API_KEY", None)
    
    print("🔑 API Key Status:")
    print("  • Regular API Key: {}".format("✅ Found" if regular_key else "❌ Missing"))
    print("  • Admin API Key: {}".format("✅ Found" if admin_key else "❌ Missing"))
    print("")
    
    # Check local usage data
    local_stats = get_local_usage_stats()
    print(local_stats)
    print("")
    
    # Show available features
    print("🚀 Available Features:")
    if regular_key:
        print("  • ✅ Basic EmberScale functionality")
    if admin_key:
        print("  • ✅ Comprehensive usage analytics")
        print("  • ✅ Cost tracking and reporting")
        print("  • ✅ API key management")
        print("  • ✅ Usage trends and insights")
    else:
        print("  • ⚠️  Limited to basic functionality (Admin API key needed for full features)")

if __name__ == "__main__":
    main()
