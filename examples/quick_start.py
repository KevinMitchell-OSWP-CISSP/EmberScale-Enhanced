#!/usr/bin/env python3
"""
EmberScale Quick Start Example
Demonstrates basic usage of EmberScale for reverse engineering
"""

import os
import sys

# Add the parent directory to the path to import decyx modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decyx.api import get_response_from_claude
from decyx.config import CLAUDE_MODELS, DEFAULT_MODEL
from decyx.logger import get_logger

# Initialize logger
logger = get_logger("QuickStart")

def quick_analysis_example():
    """
    Example of performing a quick analysis using EmberScale
    """
    print("=== EmberScale Quick Start Example ===\n")
    
    # 1. Check API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("❌ No API key found. Please set ANTHROPIC_API_KEY environment variable.")
        print("   Example: export ANTHROPIC_API_KEY=sk-ant-your-key-here")
        return False
    
    print("✅ API key found")
    
    # 2. Select model
    model = DEFAULT_MODEL
    print(f"✅ Using model: {model}")
    
    # 3. Create analysis prompt
    prompt = """
    Analyze the following function and provide:
    1. Function purpose and behavior
    2. Key variables and their roles
    3. Potential security concerns
    4. Suggested improvements
    
    Function code:
    ```c
    int process_data(char* input, int length) {
        char buffer[256];
        if (length > 256) {
            return -1;
        }
        strcpy(buffer, input);
        return strlen(buffer);
    }
    ```
    """
    
    print("✅ Analysis prompt created")
    
    # 4. Perform analysis (simulated - would need actual Ghidra environment)
    print("✅ Analysis completed (simulated)")
    print("\n📊 Analysis Results:")
    print("   • Function: process_data")
    print("   • Purpose: Data processing with buffer operations")
    print("   • Security: Potential buffer overflow vulnerability")
    print("   • Recommendation: Use strncpy with bounds checking")
    
    return True

def advanced_analysis_example():
    """
    Example of advanced analysis features
    """
    print("\n=== Advanced Analysis Features ===\n")
    
    # Simulate advanced analysis
    analysis_types = [
        "Malware Detection",
        "Vulnerability Assessment", 
        "Code Obfuscation Analysis",
        "Cryptographic Function Detection",
        "Network Communication Analysis"
    ]
    
    print("🔍 Available Analysis Types:")
    for i, analysis_type in enumerate(analysis_types, 1):
        print(f"   {i}. {analysis_type}")
    
    print("\n📈 Analysis Capabilities:")
    print("   • AI-powered function analysis")
    print("   • Automated vulnerability detection")
    print("   • Intelligent code commenting")
    print("   • Cross-reference analysis")
    print("   • String pattern recognition")
    
    return True

def usage_monitoring_example():
    """
    Example of usage monitoring features
    """
    print("\n=== Usage Monitoring Features ===\n")
    
    # Simulate usage tracking
    usage_stats = {
        "total_analyses": 42,
        "tokens_used": 15680,
        "cost_estimate": "$0.47",
        "most_used_feature": "Function Analysis",
        "average_analysis_time": "2.3 seconds"
    }
    
    print("📊 Usage Statistics:")
    for key, value in usage_stats.items():
        print(f"   • {key.replace('_', ' ').title()}: {value}")
    
    print("\n💡 Optimization Tips:")
    print("   • Use batch analysis for multiple functions")
    print("   • Enable caching for repeated analyses")
    print("   • Monitor token usage to control costs")
    print("   • Use appropriate model for analysis complexity")
    
    return True

def main():
    """
    Main function demonstrating EmberScale capabilities
    """
    print("🚀 EmberScale Quick Start Guide")
    print("=" * 50)
    
    # Run examples
    success = True
    
    try:
        success &= quick_analysis_example()
        success &= advanced_analysis_example()
        success &= usage_monitoring_example()
        
        if success:
            print("\n✅ All examples completed successfully!")
            print("\n🎯 Next Steps:")
            print("   1. Install Ghidra if not already installed")
            print("   2. Set up your Anthropic API key")
            print("   3. Run EmberScale scripts in Ghidra")
            print("   4. Explore advanced features and Agent Skills")
        else:
            print("\n❌ Some examples failed. Check the error messages above.")
            
    except Exception as e:
        logger.error(f"Example execution failed: {str(e)}")
        print(f"\n❌ Error: {str(e)}")
        return False
    
    return success

if __name__ == "__main__":
    main()
