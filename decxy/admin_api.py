# -*- coding: utf-8 -*-
# admin_api.py
#
# Anthropic Admin API client for usage monitoring and cost tracking
# Provides comprehensive analytics for EmberScale tool usage

import os
import json
from datetime import datetime, timedelta
from ghidra.framework.preferences import Preferences

# -------------------------
# Admin API Configuration
# -------------------------
ADMIN_API_BASE_URL = "https://api.anthropic.com/v1/organizations"
ANTHROPIC_VERSION = "2023-06-01"

# -------------------------
# Admin API Key Management
# -------------------------
def get_admin_api_key():
    """
    Get Admin API key from preferences or environment.
    Admin API key is different from regular API key and has broader permissions.
    """
    prefs = Preferences.getUserPreferences()
    key = prefs.getString("ANTHROPIC_ADMIN_API_KEY", None)
    if key:
        return key
    
    # Check environment variables
    key = os.environ.get("ANTHROPIC_ADMIN_API_KEY") or os.environ.get("ANTHROPIC_ADMIN_KEY")
    if key:
        # Save to preferences for future use
        prefs.putString("ANTHROPIC_ADMIN_API_KEY", key)
        prefs.flush()
        print("Stored Anthropic Admin API key in Preferences")
        return key
    
    try:
        entered = askString("Anthropic Admin API Key", 
                          "Enter your Anthropic Admin API key (for usage monitoring):", "")
        if entered and entered.strip():
            key = entered.strip()
            prefs.putString("ANTHROPIC_ADMIN_API_KEY", key)
            prefs.flush()
            print("Stored Anthropic Admin API key in Preferences")
            return key
    except Exception:
        pass
    
    print("WARNING: Admin API key not found. Usage monitoring will be disabled.")
    return None

# -------------------------
# Java HTTPS Transport for Admin API
# -------------------------
def admin_api_request(endpoint, params=None):
    """
    Make authenticated request to Anthropic Admin API.
    Returns parsed JSON response or None on error.
    """
    admin_key = get_admin_api_key()
    if not admin_key:
        return None
    
    try:
        from java.net import URL
        from java.io import DataOutputStream, BufferedReader, InputStreamReader
        from javax.net.ssl import HttpsURLConnection, SSLContext, X509TrustManager
        from java.security import SecureRandom
        import urllib.parse

        class TrustAllManager(X509TrustManager):
            def checkClientTrusted(self, chain, authType): pass
            def checkServerTrusted(self, chain, authType): pass
            def getAcceptedIssuers(self): return None

        ssl_ctx = SSLContext.getInstance("SSL")
        ssl_ctx.init(None, [TrustAllManager()], SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(ssl_ctx.getSocketFactory())

        # Build URL with parameters
        url = ADMIN_API_BASE_URL + endpoint
        if params:
            param_str = urllib.parse.urlencode(params)
            url += "?" + param_str

        u = URL(url)
        con = u.openConnection()
        con.setRequestMethod("GET")
        con.setDoOutput(False)
        con.setConnectTimeout(30000)
        con.setReadTimeout(30000)
        con.setRequestProperty("Content-Type", "application/json")
        con.setRequestProperty("anthropic-version", ANTHROPIC_VERSION)
        con.setRequestProperty("x-api-key", admin_key)

        code = con.getResponseCode()
        if code != 200:
            print("Admin API HTTP {}: {}".format(code, con.getResponseMessage()))
            return None

        br = BufferedReader(InputStreamReader(con.getInputStream()))
        buf = []
        line = br.readLine()
        while line is not None:
            buf.append(line)
            line = br.readLine()
        br.close()

        return json.loads("".join(buf))
    except Exception as e:
        print("Admin API request failed: {}".format(str(e)))
        return None

# -------------------------
# Usage Report Functions
# -------------------------
def get_usage_report(start_date=None, end_date=None, group_by=None, limit=7):
    """
    Get usage report for Messages API.
    
    Args:
        start_date: Start date in RFC 3339 format (default: 7 days ago)
        end_date: End date in RFC 3339 format (default: now)
        group_by: List of grouping options ['api_key_id', 'workspace_id', 'model', 'service_tier', 'context_window']
        limit: Number of time buckets (default: 7)
    
    Returns:
        Dictionary with usage data or None on error
    """
    if not start_date:
        start_date = (datetime.now() - timedelta(days=7)).isoformat() + "Z"
    if not end_date:
        end_date = datetime.now().isoformat() + "Z"
    
    params = {
        "starting_at": start_date,
        "ending_at": end_date,
        "bucket_width": "1d",
        "limit": limit
    }
    
    if group_by:
        params["group_by[]"] = group_by
    
    return admin_api_request("/usage_report/messages", params)

def get_cost_report(start_date=None, end_date=None, group_by=None, limit=7):
    """
    Get cost report for API usage.
    
    Args:
        start_date: Start date in RFC 3339 format (default: 7 days ago)
        end_date: End date in RFC 3339 format (default: now)
        group_by: List of grouping options ['workspace_id', 'description']
        limit: Number of time buckets (default: 7)
    
    Returns:
        Dictionary with cost data or None on error
    """
    if not start_date:
        start_date = (datetime.now() - timedelta(days=7)).isoformat() + "Z"
    if not end_date:
        end_date = datetime.now().isoformat() + "Z"
    
    params = {
        "starting_at": start_date,
        "ending_at": end_date,
        "bucket_width": "1d",
        "limit": limit
    }
    
    if group_by:
        params["group_by[]"] = group_by
    
    return admin_api_request("/cost_report", params)

def get_claude_code_usage(start_date=None, limit=20):
    """
    Get Claude Code usage report.
    
    Args:
        start_date: Date in YYYY-MM-DD format (default: today)
        limit: Number of records per page (default: 20)
    
    Returns:
        Dictionary with Claude Code usage data or None on error
    """
    if not start_date:
        start_date = datetime.now().strftime("%Y-%m-%d")
    
    params = {
        "starting_at": start_date,
        "limit": limit
    }
    
    return admin_api_request("/usage_report/claude_code", params)

def list_api_keys(status=None, workspace_id=None, limit=20):
    """
    List API keys with optional filtering.
    
    Args:
        status: Filter by status ['active', 'inactive', 'archived']
        workspace_id: Filter by workspace ID
        limit: Number of items per page (default: 20)
    
    Returns:
        Dictionary with API key list or None on error
    """
    params = {"limit": limit}
    
    if status:
        params["status"] = status
    if workspace_id:
        params["workspace_id"] = workspace_id
    
    return admin_api_request("/api_keys", params)

# -------------------------
# Usage Analytics and Reporting
# -------------------------
def analyze_usage_trends(usage_data):
    """
    Analyze usage trends from usage report data.
    
    Args:
        usage_data: Usage report data from get_usage_report()
    
    Returns:
        Dictionary with trend analysis
    """
    if not usage_data or "data" not in usage_data:
        return None
    
    trends = {
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_cost": 0,
        "daily_averages": [],
        "model_usage": {},
        "service_tier_usage": {},
        "context_window_usage": {}
    }
    
    for bucket in usage_data["data"]:
        daily_input = 0
        daily_output = 0
        
        for result in bucket.get("results", []):
            # Aggregate tokens
            daily_input += result.get("uncached_input_tokens", 0)
            daily_input += result.get("cache_read_input_tokens", 0)
            daily_output += result.get("output_tokens", 0)
            
            # Track by model
            model = result.get("model")
            if model:
                if model not in trends["model_usage"]:
                    trends["model_usage"][model] = {"input": 0, "output": 0}
                trends["model_usage"][model]["input"] += daily_input
                trends["model_usage"][model]["output"] += daily_output
            
            # Track by service tier
            tier = result.get("service_tier")
            if tier:
                if tier not in trends["service_tier_usage"]:
                    trends["service_tier_usage"][tier] = 0
                trends["service_tier_usage"][tier] += daily_input + daily_output
            
            # Track by context window
            context = result.get("context_window")
            if context:
                if context not in trends["context_window_usage"]:
                    trends["context_window_usage"][context] = 0
                trends["context_window_usage"][context] += daily_input + daily_output
        
        trends["total_input_tokens"] += daily_input
        trends["total_output_tokens"] += daily_output
        trends["daily_averages"].append({
            "date": bucket.get("starting_at", ""),
            "input_tokens": daily_input,
            "output_tokens": daily_output
        })
    
    return trends

def generate_usage_summary():
    """
    Generate a comprehensive usage summary for the current user.
    
    Returns:
        Formatted string with usage summary
    """
    print("Fetching usage data...")
    
    # Get usage report
    usage_data = get_usage_report()
    if not usage_data:
        return "Unable to fetch usage data. Check Admin API key configuration."
    
    # Analyze trends
    trends = analyze_usage_trends(usage_data)
    if not trends:
        return "No usage data available for analysis."
    
    # Generate summary
    summary = []
    summary.append("=== EmberScale Usage Summary ===")
    summary.append("")
    summary.append("📊 Token Usage:")
    summary.append("  • Total Input Tokens: {:,}".format(trends["total_input_tokens"]))
    summary.append("  • Total Output Tokens: {:,}".format(trends["total_output_tokens"]))
    summary.append("")
    
    if trends["model_usage"]:
        summary.append("🤖 Model Usage:")
        for model, usage in trends["model_usage"].items():
            summary.append("  • {}: {:,} input, {:,} output tokens".format(
                model, usage["input"], usage["output"]))
        summary.append("")
    
    if trends["service_tier_usage"]:
        summary.append("⚡ Service Tier Usage:")
        for tier, tokens in trends["service_tier_usage"].items():
            summary.append("  • {}: {:,} tokens".format(tier, tokens))
        summary.append("")
    
    if trends["context_window_usage"]:
        summary.append("📏 Context Window Usage:")
        for context, tokens in trends["context_window_usage"].items():
            summary.append("  • {}: {:,} tokens".format(context, tokens))
        summary.append("")
    
    # Daily breakdown
    summary.append("📅 Daily Breakdown:")
    for day in trends["daily_averages"][-7:]:  # Last 7 days
        date_str = day["date"][:10] if day["date"] else "Unknown"
        summary.append("  • {}: {:,} input, {:,} output tokens".format(
            date_str, day["input_tokens"], day["output_tokens"]))
    
    return "\n".join(summary)

# -------------------------
# Cost Analysis
# -------------------------
def analyze_costs(cost_data):
    """
    Analyze cost data from cost report.
    
    Args:
        cost_data: Cost report data from get_cost_report()
    
    Returns:
        Dictionary with cost analysis
    """
    if not cost_data or "data" not in cost_data:
        return None
    
    analysis = {
        "total_cost": 0,
        "daily_costs": [],
        "cost_by_type": {},
        "cost_by_model": {},
        "cost_by_workspace": {}
    }
    
    for bucket in cost_data["data"]:
        daily_cost = 0
        
        for result in bucket.get("results", []):
            amount = float(result.get("amount", 0))
            daily_cost += amount
            
            # Track by cost type
            cost_type = result.get("cost_type")
            if cost_type:
                if cost_type not in analysis["cost_by_type"]:
                    analysis["cost_by_type"][cost_type] = 0
                analysis["cost_by_type"][cost_type] += amount
            
            # Track by model
            model = result.get("model")
            if model:
                if model not in analysis["cost_by_model"]:
                    analysis["cost_by_model"][model] = 0
                analysis["cost_by_model"][model] += amount
            
            # Track by workspace
            workspace = result.get("workspace_id")
            if workspace:
                if workspace not in analysis["cost_by_workspace"]:
                    analysis["cost_by_workspace"][workspace] = 0
                analysis["cost_by_workspace"][workspace] += amount
        
        analysis["total_cost"] += daily_cost
        analysis["daily_costs"].append({
            "date": bucket.get("starting_at", ""),
            "cost": daily_cost
        })
    
    return analysis

def generate_cost_summary():
    """
    Generate a comprehensive cost summary.
    
    Returns:
        Formatted string with cost summary
    """
    print("Fetching cost data...")
    
    # Get cost report
    cost_data = get_cost_report()
    if not cost_data:
        return "Unable to fetch cost data. Check Admin API key configuration."
    
    # Analyze costs
    analysis = analyze_costs(cost_data)
    if not analysis:
        return "No cost data available for analysis."
    
    # Generate summary
    summary = []
    summary.append("=== EmberScale Cost Summary ===")
    summary.append("")
    summary.append("💰 Total Cost: ${:.2f}".format(analysis["total_cost"]))
    summary.append("")
    
    if analysis["cost_by_type"]:
        summary.append("📊 Cost by Type:")
        for cost_type, amount in analysis["cost_by_type"].items():
            summary.append("  • {}: ${:.2f}".format(cost_type, amount))
        summary.append("")
    
    if analysis["cost_by_model"]:
        summary.append("🤖 Cost by Model:")
        for model, amount in analysis["cost_by_model"].items():
            summary.append("  • {}: ${:.2f}".format(model, amount))
        summary.append("")
    
    if analysis["cost_by_workspace"]:
        summary.append("🏢 Cost by Workspace:")
        for workspace, amount in analysis["cost_by_workspace"].items():
            summary.append("  • {}: ${:.2f}".format(workspace, amount))
        summary.append("")
    
    # Daily breakdown
    summary.append("📅 Daily Costs:")
    for day in analysis["daily_costs"][-7:]:  # Last 7 days
        date_str = day["date"][:10] if day["date"] else "Unknown"
        summary.append("  • {}: ${:.2f}".format(date_str, day["cost"]))
    
    return "\n".join(summary)

# -------------------------
# API Key Management
# -------------------------
def get_api_key_info():
    """
    Get information about available API keys.
    
    Returns:
        Formatted string with API key information
    """
    print("Fetching API key information...")
    
    keys_data = list_api_keys()
    if not keys_data:
        return "Unable to fetch API key information. Check Admin API key configuration."
    
    summary = []
    summary.append("=== API Key Information ===")
    summary.append("")
    
    for key in keys_data.get("data", []):
        summary.append("🔑 {} ({})".format(key.get("name", "Unknown"), key.get("id", "Unknown")))
        summary.append("  • Status: {}".format(key.get("status", "Unknown")))
        summary.append("  • Created: {}".format(key.get("created_at", "Unknown")[:10]))
        summary.append("  • Workspace: {}".format(key.get("workspace_id", "Default")))
        summary.append("  • Hint: {}".format(key.get("partial_key_hint", "N/A")))
        summary.append("")
    
    return "\n".join(summary)

# -------------------------
# Main Usage Dashboard
# -------------------------
def show_usage_dashboard():
    """
    Display comprehensive usage dashboard.
    """
    print("=== EmberScale Usage Dashboard ===")
    print("")
    
    # Show usage summary
    usage_summary = generate_usage_summary()
    print(usage_summary)
    print("")
    
    # Show cost summary
    cost_summary = generate_cost_summary()
    print(cost_summary)
    print("")
    
    # Show API key info
    key_info = get_api_key_info()
    print(key_info)

# -------------------------
# Integration with existing API key management
# -------------------------
def enhance_api_key_management():
    """
    Enhance the existing API key management with usage monitoring.
    """
    # This function can be called from the main scripts to add usage monitoring
    # to the existing API key saving functionality
    
    print("Enhanced API key management with usage monitoring enabled.")
    print("Use show_usage_dashboard() to view comprehensive usage analytics.")
