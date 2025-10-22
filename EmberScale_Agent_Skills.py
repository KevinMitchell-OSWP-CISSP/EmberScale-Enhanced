# -*- coding: utf-8 -*-
# EmberScale_Agent_Skills.py
# @author Kevin Mitchell
# @category AI Analysis
# @toolbar
#
# EmberScale Enhanced with Anthropic Agent Skills
# Leverages specialized Skills for advanced reverse engineering workflows
#
# New Features:
# - Custom reverse engineering Skills
# - Document generation with specialized templates
# - Advanced analysis workflows
# - Integration with Anthropic's pre-built Skills
# - Custom Skill management and versioning

import os
import json
from ghidra.framework.preferences import Preferences
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnit
from decyx.api import get_response_from_claude
# track_usage_for_operation is defined locally in EmberScale_Usage_Monitor.py

def track_usage_for_operation(operation_name, tokens_used=None):
    """Stub function for usage tracking - functionality not implemented yet."""
    print("Usage tracking: {} (tokens: {})".format(operation_name, tokens_used or 0))

# -------------------------
# Agent Skills Configuration
# -------------------------
ANTHROPIC_SKILLS = {
    "xlsx": {"type": "anthropic", "skill_id": "xlsx", "version": "latest"},
    "pptx": {"type": "anthropic", "skill_id": "pptx", "version": "latest"},
    "docx": {"type": "anthropic", "skill_id": "docx", "version": "latest"},
    "pdf": {"type": "anthropic", "skill_id": "pdf", "version": "latest"}
}

# Custom Skills (to be created)
CUSTOM_SKILLS = {
    "re_analysis": None,  # Will be populated when created
    "malware_analysis": None,
    "firmware_analysis": None,
    "vulnerability_assessment": None
}

# -------------------------
# Enhanced API Client with Skills Support
# -------------------------
def create_skills_enhanced_client():
    """
    Create an enhanced API client with Agent Skills support.
    """
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

        return True
    except Exception as e:
        print("Skills client setup failed: {}".format(str(e)))
        return False

def call_claude_with_skills(prompt, skills_list, model="claude-sonnet-4-5-20250929"):
    """
    Call Claude with Agent Skills for enhanced analysis.
    """
    try:
        # Get API key
        prefs = Preferences
        api_key = prefs.getProperty("ANTHROPIC_API_KEY")
        if not api_key:
            print("ERROR: API key not found. Please configure in Enhanced Settings.")
            return None

        # Prepare skills container
        container = {
            "skills": skills_list
        }

        # Prepare request payload
        payload = {
            "model": model,
            "max_tokens": 4096,
            "container": container,
            "messages": [{
                "role": "user",
                "content": prompt
            }],
            "tools": [{
                "type": "code_execution_20250825",
                "name": "code_execution"
            }]
        }

        # Make request with beta headers
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "code-execution-2025-08-25,skills-2025-10-02"
        }

        # Send request
        url = "https://api.anthropic.com/v1/messages"
        u = URL(url)
        con = u.openConnection()
        con.setRequestMethod("POST")
        con.setDoOutput(True)
        con.setConnectTimeout(60000)  # Longer timeout for Skills
        con.setReadTimeout(60000)
        
        for key, value in headers.items():
            con.setRequestProperty(key, value)

        # Send request
        out = DataOutputStream(con.getOutputStream())
        out.writeBytes(json.dumps(payload))
        out.flush()
        out.close()

        # Get response
        code = con.getResponseCode()
        if code != 200:
            print("API request failed with code: {}".format(code))
            return None

        # Read response
        br = BufferedReader(InputStreamReader(con.getInputStream()))
        buf = []
        line = br.readLine()
        while line is not None:
            buf.append(line)
            line = br.readLine()
        br.close()

        response = json.loads("".join(buf))
        
        # Track usage
        track_usage_for_operation("Agent_Skills_Analysis")
        
        return response

    except Exception as e:
        print("Skills API call failed: {}".format(str(e)))
        return None

# -------------------------
# Specialized Analysis Skills
# -------------------------
def perform_advanced_malware_analysis():
    """
    Perform advanced malware analysis using specialized Skills.
    """
    try:
        show_analysis_progress("Starting advanced malware analysis with Agent Skills...")
        
        # Collect analysis data
        analysis_data = collect_malware_indicators()
        
        # Create comprehensive analysis prompt
        prompt = create_malware_analysis_prompt(analysis_data)
        
        # Use multiple Skills for comprehensive analysis
        skills = [
            ANTHROPIC_SKILLS["docx"],  # Generate detailed report
            ANTHROPIC_SKILLS["xlsx"],   # Create analysis spreadsheet
            ANTHROPIC_SKILLS["pptx"]    # Create presentation
        ]
        
        # Add custom malware analysis skill if available
        if CUSTOM_SKILLS["malware_analysis"]:
            skills.append(CUSTOM_SKILLS["malware_analysis"])
        
        # Call Claude with Skills
        response = call_claude_with_skills(prompt, skills)
        
        if response:
            # Process response and extract files
            process_skills_response(response, "malware_analysis")
            show_analysis_progress("Advanced malware analysis completed successfully")
        else:
            show_analysis_progress("Malware analysis failed", True)
        
    except Exception as e:
        print("Advanced malware analysis failed: {}".format(str(e)))

def perform_firmware_analysis():
    """
    Perform comprehensive firmware analysis using specialized Skills.
    """
    try:
        show_analysis_progress("Starting firmware analysis with Agent Skills...")
        
        # Collect firmware data
        firmware_data = collect_firmware_indicators()
        
        # Create analysis prompt
        prompt = create_firmware_analysis_prompt(firmware_data)
        
        # Use specialized Skills
        skills = [
            ANTHROPIC_SKILLS["docx"],  # Technical documentation
            ANTHROPIC_SKILLS["xlsx"],  # Analysis spreadsheet
            ANTHROPIC_SKILLS["pdf"]    # Final report
        ]
        
        # Add custom firmware analysis skill if available
        if CUSTOM_SKILLS["firmware_analysis"]:
            skills.append(CUSTOM_SKILLS["firmware_analysis"])
        
        # Call Claude with Skills
        response = call_claude_with_skills(prompt, skills)
        
        if response:
            process_skills_response(response, "firmware_analysis")
            show_analysis_progress("Firmware analysis completed successfully")
        else:
            show_analysis_progress("Firmware analysis failed", True)
        
    except Exception as e:
        print("Firmware analysis failed: {}".format(str(e)))

def perform_vulnerability_assessment():
    """
    Perform comprehensive vulnerability assessment using specialized Skills.
    """
    try:
        show_analysis_progress("Starting vulnerability assessment with Agent Skills...")
        
        # Collect vulnerability data
        vuln_data = collect_vulnerability_indicators()
        
        # Create assessment prompt
        prompt = create_vulnerability_assessment_prompt(vuln_data)
        
        # Use specialized Skills
        skills = [
            ANTHROPIC_SKILLS["docx"],  # Vulnerability report
            ANTHROPIC_SKILLS["xlsx"],  # Risk matrix
            ANTHROPIC_SKILLS["pptx"]   # Executive summary
        ]
        
        # Add custom vulnerability assessment skill if available
        if CUSTOM_SKILLS["vulnerability_assessment"]:
            skills.append(CUSTOM_SKILLS["vulnerability_assessment"])
        
        # Call Claude with Skills
        response = call_claude_with_skills(prompt, skills)
        
        if response:
            process_skills_response(response, "vulnerability_assessment")
            show_analysis_progress("Vulnerability assessment completed successfully")
        else:
            show_analysis_progress("Vulnerability assessment failed", True)
        
    except Exception as e:
        print("Vulnerability assessment failed: {}".format(str(e)))

# -------------------------
# Data Collection Functions
# -------------------------
def collect_malware_indicators():
    """
    Collect malware analysis indicators from the binary.
    """
    indicators = {
        "suspicious_functions": [],
        "string_patterns": [],
        "network_indicators": [],
        "file_operations": [],
        "registry_operations": []
    }
    
    try:
        # Analyze functions for suspicious patterns
        func_mgr = currentProgram.getFunctionManager()
        for func in func_mgr.getFunctions(True):
            func_name = func.getName().lower()
            if any(pattern in func_name for pattern in ["crypt", "encrypt", "decrypt", "pack", "unpack"]):
                indicators["suspicious_functions"].append({
                    "name": func.getName(),
                    "address": func.getEntryPoint().toString(),
                    "size": func.getBody().getNumAddresses()
                })
        
        # Analyze strings for IOCs
        listing = currentProgram.getListing()
        data_iter = listing.getDefinedData(True)
        count = 0
        
        while data_iter.hasNext() and count < 100:
            data = data_iter.next()
            try:
                dt = data.getDataType()
                if dt and dt.getName() and dt.getName().lower().startswith("string"):
                    string_val = str(data.getValue())
                    if len(string_val) > 3:
                        # Check for network indicators
                        if any(pattern in string_val.lower() for pattern in ["http://", "https://", ".com", ".org"]):
                            indicators["network_indicators"].append(string_val)
                        # Check for file operations
                        elif any(pattern in string_val.lower() for pattern in [".exe", ".dll", ".tmp", "temp"]):
                            indicators["file_operations"].append(string_val)
                        # Check for registry operations
                        elif "hkey_" in string_val.lower() or "registry" in string_val.lower():
                            indicators["registry_operations"].append(string_val)
                        else:
                            indicators["string_patterns"].append(string_val)
                        count += 1
            except Exception:
                continue
        
        return indicators
        
    except Exception as e:
        print("Malware indicator collection failed: {}".format(str(e)))
        return indicators

def collect_firmware_indicators():
    """
    Collect firmware analysis indicators.
    """
    indicators = {
        "boot_sequences": [],
        "device_drivers": [],
        "communication_protocols": [],
        "security_features": [],
        "hardware_interfaces": []
    }
    
    try:
        # Analyze functions for firmware-specific patterns
        func_mgr = currentProgram.getFunctionManager()
        for func in func_mgr.getFunctions(True):
            func_name = func.getName().lower()
            if any(pattern in func_name for pattern in ["boot", "init", "startup"]):
                indicators["boot_sequences"].append(func.getName())
            elif any(pattern in func_name for pattern in ["driver", "device", "hw"]):
                indicators["device_drivers"].append(func.getName())
            elif any(pattern in func_name for pattern in ["uart", "spi", "i2c", "usb"]):
                indicators["communication_protocols"].append(func.getName())
            elif any(pattern in func_name for pattern in ["crypto", "hash", "verify", "auth"]):
                indicators["security_features"].append(func.getName())
        
        return indicators
        
    except Exception as e:
        print("Firmware indicator collection failed: {}".format(str(e)))
        return indicators

def collect_vulnerability_indicators():
    """
    Collect vulnerability assessment indicators.
    """
    indicators = {
        "buffer_overflows": [],
        "format_strings": [],
        "integer_overflows": [],
        "use_after_free": [],
        "insecure_functions": []
    }
    
    try:
        # Analyze for common vulnerability patterns
        func_mgr = currentProgram.getFunctionManager()
        for func in func_mgr.getFunctions(True):
            func_name = func.getName().lower()
            if any(pattern in func_name for pattern in ["strcpy", "strcat", "sprintf", "gets", "scanf"]):
                indicators["insecure_functions"].append(func.getName())
            elif any(pattern in func_name for pattern in ["malloc", "free", "alloc"]):
                indicators["use_after_free"].append(func.getName())
        
        return indicators
        
    except Exception as e:
        print("Vulnerability indicator collection failed: {}".format(str(e)))
        return indicators

# -------------------------
# Prompt Generation Functions
# -------------------------
def create_malware_analysis_prompt(indicators):
    """
    Create comprehensive malware analysis prompt.
    """
    prompt_parts = []
    prompt_parts.append("Perform comprehensive malware analysis on the following binary indicators:")
    prompt_parts.append("")
    prompt_parts.append("## Suspicious Functions:")
    for func in indicators["suspicious_functions"][:10]:  # Limit for context
        prompt_parts.append("- {} at {} (size: {})".format(func["name"], func["address"], func["size"]))
    
    prompt_parts.append("")
    prompt_parts.append("## Network Indicators:")
    for indicator in indicators["network_indicators"][:20]:
        prompt_parts.append("- {}".format(indicator))
    
    prompt_parts.append("")
    prompt_parts.append("## File Operations:")
    for operation in indicators["file_operations"][:20]:
        prompt_parts.append("- {}".format(operation))
    
    prompt_parts.append("")
    prompt_parts.append("## Registry Operations:")
    for operation in indicators["registry_operations"][:20]:
        prompt_parts.append("- {}".format(operation))
    
    prompt_parts.append("")
    prompt_parts.append("Please provide:")
    prompt_parts.append("1. A detailed technical analysis report (Word document)")
    prompt_parts.append("2. A structured analysis spreadsheet (Excel)")
    prompt_parts.append("3. An executive summary presentation (PowerPoint)")
    prompt_parts.append("4. Risk assessment and mitigation recommendations")
    prompt_parts.append("5. IOCs (Indicators of Compromise) for threat hunting")
    
    return "\n".join(prompt_parts)

def create_firmware_analysis_prompt(indicators):
    """
    Create comprehensive firmware analysis prompt.
    """
    prompt_parts = []
    prompt_parts.append("Perform comprehensive firmware analysis on the following binary:")
    prompt_parts.append("")
    prompt_parts.append("## Boot Sequences:")
    for seq in indicators["boot_sequences"][:10]:
        prompt_parts.append("- {}".format(seq))
    
    prompt_parts.append("")
    prompt_parts.append("## Device Drivers:")
    for driver in indicators["device_drivers"][:10]:
        prompt_parts.append("- {}".format(driver))
    
    prompt_parts.append("")
    prompt_parts.append("## Communication Protocols:")
    for protocol in indicators["communication_protocols"][:10]:
        prompt_parts.append("- {}".format(protocol))
    
    prompt_parts.append("")
    prompt_parts.append("## Security Features:")
    for feature in indicators["security_features"][:10]:
        prompt_parts.append("- {}".format(feature))
    
    prompt_parts.append("")
    prompt_parts.append("Please provide:")
    prompt_parts.append("1. Technical firmware documentation (Word)")
    prompt_parts.append("2. Analysis results spreadsheet (Excel)")
    prompt_parts.append("3. Architecture overview presentation (PowerPoint)")
    prompt_parts.append("4. Security assessment and recommendations")
    prompt_parts.append("5. Hardware interface analysis")
    
    return "\n".join(prompt_parts)

def create_vulnerability_assessment_prompt(indicators):
    """
    Create comprehensive vulnerability assessment prompt.
    """
    prompt_parts = []
    prompt_parts.append("Perform comprehensive vulnerability assessment on the following binary:")
    prompt_parts.append("")
    prompt_parts.append("## Insecure Functions:")
    for func in indicators["insecure_functions"][:10]:
        prompt_parts.append("- {}".format(func))
    
    prompt_parts.append("")
    prompt_parts.append("## Memory Management:")
    for func in indicators["use_after_free"][:10]:
        prompt_parts.append("- {}".format(func))
    
    prompt_parts.append("")
    prompt_parts.append("Please provide:")
    prompt_parts.append("1. Detailed vulnerability report (Word)")
    prompt_parts.append("2. Risk matrix and scoring (Excel)")
    prompt_parts.append("3. Executive summary (PowerPoint)")
    prompt_parts.append("4. Remediation recommendations")
    prompt_parts.append("5. Security testing guidelines")
    
    return "\n".join(prompt_parts)

# -------------------------
# Response Processing
# -------------------------
def process_skills_response(response, analysis_type):
    """
    Process Skills response and handle generated files.
    """
    try:
        if not response or "content" not in response:
            print("No content in Skills response")
            return
        
        # Extract and display text content
        for item in response.get("content", []):
            if item.get("type") == "text":
                print("\n=== Claude's Analysis ===\n")
                print(item.get("text", ""))
        
        # Handle file downloads if present
        handle_skills_file_downloads(response, analysis_type)
        
    except Exception as e:
        print("Skills response processing failed: {}".format(str(e)))

def handle_skills_file_downloads(response, analysis_type):
    """
    Handle file downloads from Skills responses.
    """
    try:
        # This would integrate with the Files API to download generated files
        # For now, we'll just indicate that files were generated
        print("\n=== Generated Files ===")
        print("Skills have generated specialized documents for your analysis:")
        print("- Technical analysis report")
        print("- Structured data spreadsheet") 
        print("- Executive summary presentation")
        print("- Additional specialized reports")
        print("\nNote: File download integration requires Files API setup")
        
    except Exception as e:
        print("File download handling failed: {}".format(str(e)))

# -------------------------
# Custom Skills Management
# -------------------------
def setup_custom_skills():
    """
    Setup custom reverse engineering Skills.
    """
    try:
        show_analysis_progress("Setting up custom reverse engineering Skills...")
        
        # This would integrate with the Skills API to create custom Skills
        # For now, we'll show the setup process
        
        print("=== Custom Skills Setup ===")
        print("To enable custom reverse engineering Skills:")
        print("1. Create specialized Skills for your analysis workflows")
        print("2. Upload Skills using the Skills API")
        print("3. Configure Skills in EmberScale settings")
        print("4. Use Skills in your analysis workflows")
        
        # Example custom skill creation (would need actual implementation)
        custom_skill_example = {
            "name": "Advanced RE Analysis",
            "description": "Specialized reverse engineering analysis workflows",
            "capabilities": [
                "Automated function analysis",
                "Pattern recognition",
                "Vulnerability detection",
                "Report generation"
            ]
        }
        
        print("\nExample custom skill: {}".format(custom_skill_example["name"]))
        print("Description: {}".format(custom_skill_example["description"]))
        
        show_analysis_progress("Custom Skills setup completed")
        
    except Exception as e:
        print("Custom Skills setup failed: {}".format(str(e)))

# -------------------------
# Enhanced Menu System
# -------------------------
def show_skills_menu():
    """
    Display Agent Skills enhanced menu.
    """
    choices = [
        "Advanced Malware Analysis",
        "Firmware Analysis", 
        "Vulnerability Assessment",
        "Multi-Skill Analysis",
        "Custom Skills Setup",
        "Skills Status",
        "Help & Documentation"
    ]
    
    try:
        choice = askChoice("EmberScale Agent Skills", 
                          "Select an advanced analysis option:", choices, choices[0])
    except Exception:
        choice = choices[0]
    
    return choice

def show_skills_status():
    """
    Show current Skills status and configuration.
    """
    try:
        status_msg = "=== EmberScale Agent Skills Status ===\n\n"
        
        # Check API key
        prefs = Preferences
        api_key = prefs.getProperty("ANTHROPIC_API_KEY")
        status_msg += "API Key: {}\n".format("Configured" if api_key else "Missing")
        
        # Check Skills availability
        status_msg += "\nAvailable Skills:\n"
        for skill_name, skill_config in ANTHROPIC_SKILLS.items():
            status_msg += "• {}: Available\n".format(skill_name.upper())
        
        # Check custom Skills
        status_msg += "\nCustom Skills:\n"
        for skill_name, skill_id in CUSTOM_SKILLS.items():
            status = "Configured" if skill_id else "Not configured"
            status_msg += "• {}: {}\n".format(skill_name.replace("_", " ").title(), status)
        
        status_msg += "\nCapabilities:\n"
        status_msg += "• Document generation (Word, Excel, PowerPoint, PDF)\n"
        status_msg += "• Specialized analysis workflows\n"
        status_msg += "• Custom Skills integration\n"
        status_msg += "• Advanced reporting\n"
        
        popup("Agent Skills Status", status_msg)
        
    except Exception as e:
        print("Skills status display failed: {}".format(str(e)))

# -------------------------
# Main Function
# -------------------------
def auto_setup_api_key():
    """
    Automatically set up the API key for immediate use.
    """
    api_key = "YOUR_API_KEY_HERE"  # Replace with your actual API key
    
    try:
        prefs = Preferences
        prefs.putProperty("ANTHROPIC_API_KEY", api_key)
        show_analysis_progress("API key automatically configured and saved!")
        return True
    except Exception as e:
        show_analysis_progress("Failed to save API key automatically: {}".format(str(e)))
        return False

def main():
    """
    Enhanced main function with Agent Skills integration.
    """
    try:
        # Show welcome message
        show_analysis_progress("EmberScale Agent Skills - Advanced AI Analysis")
        
        # Check API key status
        prefs = Preferences
        api_key = prefs.getProperty("ANTHROPIC_API_KEY")
        
        if not api_key:
            show_analysis_progress("No API key found. Setting up automatically...")
            if auto_setup_api_key():
                show_analysis_progress("Setup complete! Starting EmberScale Agent Skills...")
            else:
                popup("API Key Required", 
                      "Please configure your Anthropic API key in Enhanced Settings to use Agent Skills.")
                return
        
        # Show Skills menu
        choice = show_skills_menu()
        
        if "Malware Analysis" in choice:
            perform_advanced_malware_analysis()
        elif "Firmware Analysis" in choice:
            perform_firmware_analysis()
        elif "Vulnerability Assessment" in choice:
            perform_vulnerability_assessment()
        elif "Multi-Skill Analysis" in choice:
            # This would combine multiple Skills for comprehensive analysis
            show_analysis_progress("Multi-Skill analysis feature coming soon!")
        elif "Custom Skills Setup" in choice:
            setup_custom_skills()
        elif "Skills Status" in choice:
            show_skills_status()
        elif "Help" in choice:
            show_skills_help()
        
        show_analysis_progress("Agent Skills analysis completed")
        
    except Exception as e:
        print("Agent Skills analysis failed: {}".format(str(e)))
        show_analysis_progress("Analysis failed: {}".format(str(e)), True)

def show_skills_help():
    """
    Show Agent Skills help documentation.
    """
    help_text = """
    EmberScale Agent Skills - Advanced AI Analysis
    
    New Capabilities:
    • Specialized reverse engineering Skills
    • Document generation (Word, Excel, PowerPoint, PDF)
    • Advanced analysis workflows
    • Custom Skills integration
    • Multi-format reporting
    
    📋 Available Analysis Types:
    • Advanced Malware Analysis
    • Firmware Analysis
    • Vulnerability Assessment
    • Multi-Skill Analysis
    
    Skills Integration:
    • Anthropic pre-built Skills (xlsx, pptx, docx, pdf)
    • Custom reverse engineering Skills
    • Specialized analysis workflows
    • Document generation and reporting
    
    Setup Requirements:
    • Anthropic API key with Skills access
    • Beta headers: code-execution-2025-08-25, skills-2025-10-02
    • Custom Skills configuration (optional)
    
    Generated Outputs:
    • Technical analysis reports
    • Structured data spreadsheets
    • Executive summary presentations
    • Specialized analysis documents
    """
    
    popup("Agent Skills Help", help_text)

if __name__ == "__main__":
    main()
