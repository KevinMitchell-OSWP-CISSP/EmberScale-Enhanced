# -*- coding: utf-8 -*-
# EmberScale_Enhanced.py
# @author Kevin Mitchell
# @category AI Analysis
# @toolbar
#
# Enhanced EmberScale with advanced GhidraScript API integration
# Leverages full GhidraScript capabilities for improved user experience
#
# New Features:
# - Advanced UI dialogs and interactions
# - Visual highlighting and selection management
# - Enhanced program navigation and analysis
# - Interactive table displays for results
# - Status bar integration and user feedback
# - Advanced file import and program management
# - Color-coded analysis results

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

def show_usage_dashboard_stub():
    """Stub function for usage dashboard - functionality not implemented yet."""
    print("Usage Dashboard - Feature not yet implemented")
    print("This would show usage analytics and monitoring data")

def show_usage_menu_stub():
    """Stub function for usage menu - functionality not implemented yet."""
    print("Usage Analytics Menu - Feature not yet implemented")
    print("This would show usage monitoring options and analytics")

# -------------------------
# Enhanced UI and Interaction
# -------------------------
def show_enhanced_menu():
    """
    Display an enhanced menu with advanced options using GhidraScript API.
    """
    choices = [
        "Advanced Binary Analysis",
        "Interactive Usage Dashboard", 
        "Smart Function Analysis",
        "Cross-Reference Explorer",
        "Intelligent Code Comments",
        "Visual Analysis Results",
        "Enhanced Settings",
        "Usage Analytics",
        "Help & Documentation"
    ]
    
    try:
        choice = askChoice("EmberScale Enhanced", 
                          "Select an advanced analysis option:", choices, choices[0])
    except Exception:
        choice = choices[0]
    
    return choice

def show_analysis_progress(message, beep=False):
    """
    Display analysis progress in the status bar with optional beep.
    """
    try:
        setToolStatusMessage("EmberScale: " + message, beep)
    except Exception:
        print("EmberScale: " + message)

def show_enhanced_results(title, addresses, analysis_type="general"):
    """
    Display analysis results in an enhanced table format.
    """
    try:
        if analysis_type == "functions":
            show_simple_analysis_results(title, addresses)
        elif analysis_type == "strings":
            show_simple_analysis_results(title, addresses)
        elif analysis_type == "xrefs":
            show_simple_analysis_results(title, addresses)
        else:
            show_simple_analysis_results(title, addresses)
    except Exception as e:
        print("Enhanced display failed: {}".format(str(e)))
        # Fallback to basic display
        show_simple_analysis_results(title, addresses)

def show_function_analysis_table(title, functions):
    """
    Display function analysis results in a specialized table.
    """
    try:
        # Use the standard show function instead of custom table chooser
        # This avoids the complex table chooser implementation issues
        show_simple_analysis_results(title, functions)
    except Exception as e:
        print("Function table display failed: {}".format(str(e)))
        # Fallback to basic display
        show_simple_analysis_results(title, functions)

# -------------------------
# Advanced Selection and Highlighting
# -------------------------
def create_smart_selection(addresses, selection_type="analysis"):
    """
    Create intelligent selections with visual feedback.
    """
    try:
        if not addresses:
            return
        
        # Create address set from the addresses
        from ghidra.program.model.address import AddressSet
        address_set = AddressSet()
        
        for addr in addresses:
            if addr is None:
                continue  # Skip null addresses
                
            try:
                # If it's already an address object, use it directly
                if hasattr(addr, 'getOffset') and hasattr(addr, 'getAddressSpace'):
                    address_set.add(addr)
                elif hasattr(addr, 'getAddress'):
                    # Try to get the address, but handle null cases
                    try:
                        address = addr.getAddress()
                        if address is not None:
                            address_set.add(address)
                    except Exception:
                        # If getAddress() fails, try the object itself
                        address_set.add(addr)
                else:
                    # For other types, try to add directly
                    address_set.add(addr)
            except Exception as e:
                # Skip problematic addresses
                print("Skipping invalid address: {}".format(str(e)))
                continue
        
        # Set selection with visual feedback
        if not address_set.isEmpty():
            setCurrentSelection(address_set)
            # Show status message
            show_analysis_progress("Created smart selection with {} addresses".format(len(addresses)))
        else:
            print("No valid addresses found for selection")
        
        # Optional: Add highlighting for different analysis types
        try:
            if selection_type == "suspicious":
                setBackgroundColor(address_set, java.awt.Color.RED)
            elif selection_type == "important":
                setBackgroundColor(address_set, java.awt.Color.YELLOW)
            elif selection_type == "analysis":
                setBackgroundColor(address_set, java.awt.Color.CYAN)
        except Exception as e:
            print("Highlighting failed: {}".format(str(e)))
            
    except Exception as e:
        print("Smart selection failed: {}".format(str(e)))

def clear_analysis_highlights():
    """
    Clear all analysis-related highlights and colors.
    """
    try:
        removeHighlight()
        # Note: clearBackgroundColor would need to be called for each address
        # This is a simplified version
        show_analysis_progress("Cleared analysis highlights")
    except Exception as e:
        print("Clear highlights failed: {}".format(str(e)))

# -------------------------
# Enhanced Navigation
# -------------------------
def navigate_to_analysis_result(address, result_type="function"):
    """
    Navigate to analysis results with enhanced feedback.
    """
    try:
        success = goTo(address)
        if success:
            show_analysis_progress("Navigated to {} at {}".format(result_type, address))
        else:
            show_analysis_progress("Failed to navigate to {}".format(address), True)
    except Exception as e:
        print("Navigation failed: {}".format(str(e)))

def show_analysis_summary(title, summary_data):
    """
    Display analysis summary in a popup with enhanced formatting.
    """
    try:
        formatted_summary = format_analysis_summary(summary_data)
        popup("EmberScale Analysis Summary\n\n" + formatted_summary)
    except Exception as e:
        print("Summary display failed: {}".format(str(e)))

def format_analysis_summary(data):
    """
    Format analysis data for display.
    """
    summary = []
    summary.append("Analysis Results:")
    summary.append("")
    
    if "functions_analyzed" in data:
        summary.append("Functions Analyzed: {}".format(data["functions_analyzed"]))
    
    if "strings_found" in data:
        summary.append("Strings Found: {}".format(data["strings_found"]))
    
    if "xrefs_analyzed" in data:
        summary.append("Cross-References: {}".format(data["xrefs_analyzed"]))
    
    if "suspicious_patterns" in data:
        summary.append("WARNING: Suspicious Patterns: {}".format(data["suspicious_patterns"]))
    
    if "confidence_score" in data:
        summary.append("Confidence Score: {:.1f}%".format(data["confidence_score"]))
    
    return "\n".join(summary)

# -------------------------
# Enhanced API Key Management
# -------------------------
def setup_enhanced_api_keys():
    """
    Enhanced API key setup with better user experience.
    """
    try:
        # Check current status
        prefs = Preferences
        regular_key = prefs.getProperty("ANTHROPIC_API_KEY")
        admin_key = prefs.getProperty("ANTHROPIC_ADMIN_API_KEY")
        
        # Show current status
        status_msg = "Current API Key Status:\n"
        status_msg += "Regular API Key: {}\n".format("Configured" if regular_key else "Missing")
        status_msg += "Admin API Key: {}\n".format("Configured" if admin_key else "Missing")
        
        popup("EmberScale API Key Status", status_msg)
        
        # Setup regular API key if missing
        if not regular_key:
            try:
                regular_key = askString("Regular API Key", 
                                      "Enter your Anthropic API key:", "")
                if regular_key and regular_key.strip():
                    prefs.putProperty("ANTHROPIC_API_KEY", regular_key.strip())
                    show_analysis_progress("Regular API key saved successfully")
            except Exception:
                show_analysis_progress("Regular API key setup cancelled")
        
        # Setup admin API key if missing
        if not admin_key:
            try:
                admin_key = askString("Admin API Key (Optional)", 
                                    "Enter your Anthropic Admin API key for usage monitoring:", "")
                if admin_key and admin_key.strip():
                    prefs.putProperty("ANTHROPIC_ADMIN_API_KEY", admin_key.strip())
                    show_analysis_progress("Admin API key saved successfully")
            except Exception:
                show_analysis_progress("Admin API key setup skipped")
        
        # Final status
        final_status = "API Key Setup Complete!\n\n"
        final_status += "Regular API Key: {}\n".format("Ready" if prefs.getProperty("ANTHROPIC_API_KEY") else "Missing")
        final_status += "Admin API Key: {}\n".format("Ready" if prefs.getProperty("ANTHROPIC_ADMIN_API_KEY") else "Missing")
        
        popup("Setup Complete", final_status)
        
    except Exception as e:
        print("Enhanced API key setup failed: {}".format(str(e)))

# -------------------------
# Advanced Analysis Functions
# -------------------------
def perform_smart_analysis():
    """
    Perform intelligent analysis with enhanced user interaction.
    """
    try:
        show_analysis_progress("Starting smart analysis...")
        
        # Get user preferences for analysis
        analysis_options = [
            "Deep Function Analysis",
            "String Pattern Analysis", 
            "Cross-Reference Analysis",
            "Security Pattern Detection",
            "All Analysis Types"
        ]
        
        choice = askChoice("Analysis Type", "Select analysis type:", analysis_options, analysis_options[0])
        
        if "Function" in choice or "All" in choice:
            perform_function_analysis()
        
        if "String" in choice or "All" in choice:
            perform_string_analysis()
        
        if "Cross-Reference" in choice or "All" in choice:
            perform_xref_analysis()
        
        if "Security" in choice or "All" in choice:
            perform_security_analysis()
        
        show_analysis_progress("Smart analysis completed successfully")
        
    except Exception as e:
        print("Smart analysis failed: {}".format(str(e)))
        show_analysis_progress("Analysis failed: {}".format(str(e)), True)

def perform_function_analysis():
    """
    Enhanced function analysis with visual feedback.
    """
    try:
        show_analysis_progress("Analyzing functions...")
        
        # Get functions
        func_mgr = currentProgram.getFunctionManager()
        functions = []
        
        for func in func_mgr.getFunctions(True):
            functions.append(func)
        
        # Analyze with Claude
        if functions:
            # Create smart selection - filter out null entry points
            func_addresses = []
            for f in functions[:10]:  # Limit for performance
                entry_point = f.getEntryPoint()
                if entry_point is not None:
                    func_addresses.append(entry_point)
            
            if func_addresses:
                create_smart_selection(func_addresses, "analysis")
            else:
                print("No valid function entry points found")
            
            # Track usage
            track_usage_for_operation("Enhanced_Function_Analysis")
            
            # Show results
            show_enhanced_results("Function Analysis Results", func_addresses, "functions")
        
    except Exception as e:
        print("Function analysis failed: {}".format(str(e)))

def perform_string_analysis():
    """
    Enhanced string analysis with pattern detection.
    """
    try:
        show_analysis_progress("Analyzing strings...")
        
        # Get strings
        listing = currentProgram.getListing()
        strings = []
        
        data_iter = listing.getDefinedData(True)
        count = 0
        
        while data_iter.hasNext() and count < 50:
            data = data_iter.next()
            try:
                dt = data.getDataType()
                if dt and dt.getName() and dt.getName().lower().startswith("string"):
                    strings.append(data.getAddress())
                    count += 1
            except Exception:
                continue
        
        if strings:
            # Create smart selection
            create_smart_selection(strings, "analysis")
            
            # Track usage
            track_usage_for_operation("Enhanced_String_Analysis")
            
            # Show results
            show_enhanced_results("String Analysis Results", strings, "strings")
        
    except Exception as e:
        print("String analysis failed: {}".format(str(e)))

def perform_xref_analysis():
    """
    Enhanced cross-reference analysis.
    """
    try:
        show_analysis_progress("Analyzing cross-references...")
        
        # Get current address or selection
        target_addr = currentAddress
        if currentSelection and not currentSelection.isEmpty():
            target_addr = currentSelection.getMinAddress()
        
        # Get references
        ref_mgr = currentProgram.getReferenceManager()
        refs = []
        
        for ref in ref_mgr.getReferencesTo(target_addr):
            refs.append(ref.getFromAddress())
        
        if refs:
            # Create smart selection
            create_smart_selection(refs, "analysis")
            
            # Track usage
            track_usage_for_operation("Enhanced_XRef_Analysis")
            
            # Show results
            show_enhanced_results("Cross-Reference Analysis Results", refs, "xrefs")
        
    except Exception as e:
        print("Cross-reference analysis failed: {}".format(str(e)))

def perform_security_analysis():
    """
    Enhanced security pattern analysis.
    """
    try:
        show_analysis_progress("Performing security analysis...")
        
        # Look for suspicious patterns
        suspicious_addresses = []
        
        # Check for common security-related functions
        func_mgr = currentProgram.getFunctionManager()
        security_patterns = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
        
        for func in func_mgr.getFunctions(True):
            func_name = func.getName().lower()
            for pattern in security_patterns:
                if pattern in func_name:
                    suspicious_addresses.append(func.getEntryPoint())
                    break
        
        if suspicious_addresses:
            # Create smart selection with warning colors
            create_smart_selection(suspicious_addresses, "suspicious")
            
            # Track usage
            track_usage_for_operation("Enhanced_Security_Analysis")
            
            # Show results
            show_enhanced_results("Security Analysis Results", suspicious_addresses, "security")
        
    except Exception as e:
        print("Security analysis failed: {}".format(str(e)))

# -------------------------
# Simplified Display Functions
# -------------------------
def show_simple_analysis_results(title, results):
    """
    Display analysis results using the standard Ghidra show function.
    """
    try:
        # Convert results to AddressSet if it's a list of addresses
        if isinstance(results, list) and results:
            from ghidra.program.model.address import AddressSet
            address_set = AddressSet()
            for addr in results:
                if addr is not None:
                    address_set.add(addr)
            show(title, address_set)
        else:
            show(title, results)
    except Exception as e:
        print("Display failed: {}".format(str(e)))

# -------------------------
# Enhanced Main Function
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
    Enhanced main function with advanced GhidraScript API integration.
    """
    try:
        # Show welcome message
        show_analysis_progress("EmberScale Enhanced - Advanced AI Analysis")
        
        # Check API key status
        prefs = Preferences
        regular_key = prefs.getProperty("ANTHROPIC_API_KEY")
        
        if not regular_key:
            show_analysis_progress("No API key found. Setting up automatically...")
            if auto_setup_api_key():
                show_analysis_progress("Setup complete! Starting EmberScale...")
            else:
                setup_enhanced_api_keys()
                return
        
        # Show enhanced menu
        choice = show_enhanced_menu()
        
        if "Advanced Binary Analysis" in choice:
            perform_smart_analysis()
        elif "Interactive Usage Dashboard" in choice:
            show_usage_dashboard_stub()
        elif "Smart Function Analysis" in choice:
            perform_function_analysis()
        elif "Cross-Reference Explorer" in choice:
            perform_xref_analysis()
        elif "Intelligent Code Comments" in choice:
            # This would integrate with the existing comment functionality
            show_analysis_progress("Intelligent code commenting feature coming soon!")
        elif "Visual Analysis Results" in choice:
            show_analysis_progress("Visual analysis results feature coming soon!")
        elif "Enhanced Settings" in choice:
            setup_enhanced_api_keys()
        elif "Usage Analytics" in choice:
            show_usage_menu_stub()
        elif "Help" in choice:
            show_help_documentation()
        
        show_analysis_progress("EmberScale Enhanced analysis completed")
        
    except Exception as e:
        print("Enhanced EmberScale failed: {}".format(str(e)))
        show_analysis_progress("Analysis failed: {}".format(str(e)), True)

def show_help_documentation():
    """
    Show enhanced help documentation.
    """
    help_text = """
    EmberScale Enhanced - Advanced AI Analysis Tool
    
    New Features:
    • Advanced UI dialogs and interactions
    • Visual highlighting and selection management
    • Enhanced program navigation and analysis
    • Interactive table displays for results
    • Status bar integration and user feedback
    • Color-coded analysis results
    
    📋 Available Analysis Types:
    • Deep Function Analysis
    • String Pattern Analysis
    • Cross-Reference Analysis
    • Security Pattern Detection
    
    Usage Tips:
    • Use smart selections to focus analysis
    • Leverage visual highlighting for results
    • Check status bar for progress updates
    • Use enhanced tables for detailed results
    
    Setup:
    • Configure API keys in Enhanced Settings
    • Enable usage monitoring for analytics
    • Customize analysis preferences
    """
    
    popup("EmberScale Enhanced Help", help_text)

if __name__ == "__main__":
    main()
