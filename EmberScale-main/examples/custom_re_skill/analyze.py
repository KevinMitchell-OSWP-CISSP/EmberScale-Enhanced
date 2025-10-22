#!/usr/bin/env python3
"""
Advanced Reverse Engineering Analysis Skill
Specialized binary analysis and security assessment
"""

import re
import struct
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

class AnalysisLevel(Enum):
    """Analysis sensitivity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class PatternType(Enum):
    """Pattern types for detection"""
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    SECURITY = "security"
    OBFUSCATION = "obfuscation"

@dataclass
class AnalysisResult:
    """Analysis result container"""
    pattern_type: str
    confidence: float
    description: str
    location: Optional[str] = None
    severity: str = "medium"
    recommendations: List[str] = None

@dataclass
class SecurityAssessment:
    """Security assessment result"""
    overall_risk: str
    vulnerabilities: List[AnalysisResult]
    security_features: List[str]
    recommendations: List[str]
    confidence_score: float

class BinaryAnalyzer:
    """Advanced binary analysis engine"""
    
    def __init__(self, sensitivity: AnalysisLevel = AnalysisLevel.MEDIUM):
        self.sensitivity = sensitivity
        self.patterns = self._load_patterns()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.malware_patterns = self._load_malware_patterns()
    
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load analysis patterns"""
        return {
            "suspicious_functions": [
                "strcpy", "strcat", "sprintf", "gets", "scanf",
                "malloc", "free", "realloc", "calloc",
                "CreateProcess", "WinExec", "ShellExecute",
                "RegSetValue", "RegCreateKey", "RegDeleteKey"
            ],
            "network_indicators": [
                "http://", "https://", "ftp://", "tcp://",
                "socket", "connect", "bind", "listen",
                "send", "recv", "WSAStartup", "WSACleanup"
            ],
            "file_operations": [
                "CreateFile", "WriteFile", "ReadFile", "DeleteFile",
                "CopyFile", "MoveFile", "FindFirstFile", "FindNextFile",
                "GetFileAttributes", "SetFileAttributes"
            ],
            "registry_operations": [
                "RegOpenKey", "RegCloseKey", "RegQueryValue",
                "RegSetValue", "RegDeleteValue", "RegEnumKey",
                "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"
            ]
        }
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns"""
        return {
            "buffer_overflows": [
                r"strcpy\s*\([^,]+,\s*[^)]+\)",
                r"strcat\s*\([^,]+,\s*[^)]+\)",
                r"sprintf\s*\([^,]+,\s*[^)]+\)",
                r"gets\s*\([^)]+\)"
            ],
            "format_strings": [
                r"printf\s*\([^,]+,\s*[^)]+\)",
                r"fprintf\s*\([^,]+,\s*[^)]+\)",
                r"sprintf\s*\([^,]+,\s*[^)]+\)"
            ],
            "integer_overflows": [
                r"malloc\s*\([^)]+\)",
                r"calloc\s*\([^,]+,\s*[^)]+\)",
                r"realloc\s*\([^,]+,\s*[^)]+\)"
            ]
        }
    
    def _load_malware_patterns(self) -> Dict[str, List[str]]:
        """Load malware detection patterns"""
        return {
            "packing_indicators": [
                "UPX", "PECompact", "Themida", "VMProtect",
                "ASPack", "FSG", "MEW", "Petite"
            ],
            "anti_debugging": [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "OutputDebugString"
            ],
            "code_injection": [
                "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                "CreateRemoteThread", "SetWindowsHookEx"
            ]
        }
    
    def analyze_binary_security(self, binary_data: bytes) -> SecurityAssessment:
        """Perform comprehensive security analysis"""
        vulnerabilities = []
        security_features = []
        recommendations = []
        
        # Analyze for vulnerabilities
        vulnerabilities.extend(self._detect_buffer_overflows(binary_data))
        vulnerabilities.extend(self._detect_format_strings(binary_data))
        vulnerabilities.extend(self._detect_integer_overflows(binary_data))
        
        # Analyze for security features
        security_features.extend(self._detect_security_features(binary_data))
        
        # Generate recommendations
        recommendations.extend(self._generate_recommendations(vulnerabilities))
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(vulnerabilities)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(vulnerabilities)
        
        return SecurityAssessment(
            overall_risk=overall_risk,
            vulnerabilities=vulnerabilities,
            security_features=security_features,
            recommendations=recommendations,
            confidence_score=confidence_score
        )
    
    def _detect_buffer_overflows(self, binary_data: bytes) -> List[AnalysisResult]:
        """Detect buffer overflow vulnerabilities"""
        results = []
        
        for pattern in self.vulnerability_patterns["buffer_overflows"]:
            matches = re.findall(pattern, binary_data.decode('utf-8', errors='ignore'))
            for match in matches:
                results.append(AnalysisResult(
                    pattern_type="buffer_overflow",
                    confidence=0.8,
                    description=f"Potential buffer overflow in: {match}",
                    severity="high",
                    recommendations=[
                        "Use safe string functions (strncpy, strncat)",
                        "Implement bounds checking",
                        "Use secure coding practices"
                    ]
                ))
        
        return results
    
    def _detect_format_strings(self, binary_data: bytes) -> List[AnalysisResult]:
        """Detect format string vulnerabilities"""
        results = []
        
        for pattern in self.vulnerability_patterns["format_strings"]:
            matches = re.findall(pattern, binary_data.decode('utf-8', errors='ignore'))
            for match in matches:
                results.append(AnalysisResult(
                    pattern_type="format_string",
                    confidence=0.7,
                    description=f"Potential format string vulnerability in: {match}",
                    severity="medium",
                    recommendations=[
                        "Use format string validation",
                        "Implement input sanitization",
                        "Use secure printf functions"
                    ]
                ))
        
        return results
    
    def _detect_integer_overflows(self, binary_data: bytes) -> List[AnalysisResult]:
        """Detect integer overflow vulnerabilities"""
        results = []
        
        for pattern in self.vulnerability_patterns["integer_overflows"]:
            matches = re.findall(pattern, binary_data.decode('utf-8', errors='ignore'))
            for match in matches:
                results.append(AnalysisResult(
                    pattern_type="integer_overflow",
                    confidence=0.6,
                    description=f"Potential integer overflow in: {match}",
                    severity="medium",
                    recommendations=[
                        "Implement integer overflow checks",
                        "Use safe arithmetic operations",
                        "Validate input parameters"
                    ]
                ))
        
        return results
    
    def _detect_security_features(self, binary_data: bytes) -> List[str]:
        """Detect security features in binary"""
        features = []
        
        # Check for ASLR
        if b"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" in binary_data:
            features.append("ASLR (Address Space Layout Randomization)")
        
        # Check for DEP
        if b"IMAGE_DLLCHARACTERISTICS_NX_COMPAT" in binary_data:
            features.append("DEP (Data Execution Prevention)")
        
        # Check for Stack Canaries
        if b"__stack_chk_fail" in binary_data:
            features.append("Stack Canaries")
        
        # Check for Control Flow Integrity
        if b"__guard_check_icall" in binary_data:
            features.append("Control Flow Integrity")
        
        return features
    
    def _generate_recommendations(self, vulnerabilities: List[AnalysisResult]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(v.pattern_type == "buffer_overflow" for v in vulnerabilities):
            recommendations.append("Implement buffer overflow protection mechanisms")
        
        if any(v.pattern_type == "format_string" for v in vulnerabilities):
            recommendations.append("Use secure string formatting functions")
        
        if any(v.pattern_type == "integer_overflow" for v in vulnerabilities):
            recommendations.append("Implement integer overflow detection")
        
        # General recommendations
        recommendations.extend([
            "Enable compiler security features (ASLR, DEP, Stack Canaries)",
            "Implement input validation and sanitization",
            "Use secure coding practices",
            "Regular security testing and code review",
            "Implement runtime protection mechanisms"
        ])
        
        return recommendations
    
    def _calculate_overall_risk(self, vulnerabilities: List[AnalysisResult]) -> str:
        """Calculate overall risk level"""
        if not vulnerabilities:
            return "low"
        
        high_severity = sum(1 for v in vulnerabilities if v.severity == "high")
        medium_severity = sum(1 for v in vulnerabilities if v.severity == "medium")
        
        if high_severity > 0:
            return "high"
        elif medium_severity > 2:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence_score(self, vulnerabilities: List[AnalysisResult]) -> float:
        """Calculate confidence score for analysis"""
        if not vulnerabilities:
            return 0.0
        
        total_confidence = sum(v.confidence for v in vulnerabilities)
        return total_confidence / len(vulnerabilities)
    
    def detect_malware_patterns(self, binary_data: bytes) -> List[AnalysisResult]:
        """Detect malware patterns in binary"""
        results = []
        
        # Check for packing indicators
        for indicator in self.malware_patterns["packing_indicators"]:
            if indicator.encode() in binary_data:
                results.append(AnalysisResult(
                    pattern_type="packing",
                    confidence=0.9,
                    description=f"Packed binary detected: {indicator}",
                    severity="high",
                    recommendations=[
                        "Unpack the binary for analysis",
                        "Use specialized unpacking tools",
                        "Analyze unpacked code for malicious behavior"
                    ]
                ))
        
        # Check for anti-debugging
        for indicator in self.malware_patterns["anti_debugging"]:
            if indicator.encode() in binary_data:
                results.append(AnalysisResult(
                    pattern_type="anti_debugging",
                    confidence=0.8,
                    description=f"Anti-debugging detected: {indicator}",
                    severity="medium",
                    recommendations=[
                        "Use anti-anti-debugging techniques",
                        "Analyze in controlled environment",
                        "Use specialized debugging tools"
                    ]
                ))
        
        # Check for code injection
        for indicator in self.malware_patterns["code_injection"]:
            if indicator.encode() in binary_data:
                results.append(AnalysisResult(
                    pattern_type="code_injection",
                    confidence=0.7,
                    description=f"Code injection capability: {indicator}",
                    severity="high",
                    recommendations=[
                        "Monitor for code injection attempts",
                        "Implement code integrity checks",
                        "Use application whitelisting"
                    ]
                ))
        
        return results
    
    def analyze_function_complexity(self, function_data: bytes) -> Dict[str, Any]:
        """Analyze function complexity and characteristics"""
        analysis = {
            "cyclomatic_complexity": 0,
            "instruction_count": 0,
            "branch_count": 0,
            "loop_count": 0,
            "function_calls": 0,
            "complexity_score": 0.0
        }
        
        # Basic instruction counting
        analysis["instruction_count"] = len(function_data) // 4  # Approximate
        
        # Count branches (simplified)
        branch_instructions = [b"jmp", b"je", b"jne", b"jz", b"jnz", b"call"]
        for instruction in branch_instructions:
            analysis["branch_count"] += function_data.count(instruction)
        
        # Count function calls
        analysis["function_calls"] = function_data.count(b"call")
        
        # Calculate complexity score
        analysis["complexity_score"] = (
            analysis["instruction_count"] * 0.1 +
            analysis["branch_count"] * 0.3 +
            analysis["function_calls"] * 0.2
        )
        
        return analysis

def analyze_binary_security(binary_data: bytes, sensitivity: str = "medium") -> Dict[str, Any]:
    """Main analysis function for binary security assessment"""
    try:
        # Create analyzer
        analyzer = BinaryAnalyzer(AnalysisLevel(sensitivity))
        
        # Perform security analysis
        security_assessment = analyzer.analyze_binary_security(binary_data)
        
        # Detect malware patterns
        malware_results = analyzer.detect_malware_patterns(binary_data)
        
        # Compile results
        results = {
            "security_assessment": {
                "overall_risk": security_assessment.overall_risk,
                "confidence_score": security_assessment.confidence_score,
                "vulnerabilities": [
                    {
                        "type": v.pattern_type,
                        "confidence": v.confidence,
                        "description": v.description,
                        "severity": v.severity,
                        "recommendations": v.recommendations
                    } for v in security_assessment.vulnerabilities
                ],
                "security_features": security_assessment.security_features,
                "recommendations": security_assessment.recommendations
            },
            "malware_analysis": [
                {
                    "type": m.pattern_type,
                    "confidence": m.confidence,
                    "description": m.description,
                    "severity": m.severity,
                    "recommendations": m.recommendations
                } for m in malware_results
            ],
            "analysis_metadata": {
                "sensitivity_level": sensitivity,
                "total_vulnerabilities": len(security_assessment.vulnerabilities),
                "total_malware_indicators": len(malware_results),
                "analysis_timestamp": "2025-01-27T12:00:00Z"
            }
        }
        
        return results
        
    except Exception as e:
        return {
            "error": f"Analysis failed: {str(e)}",
            "security_assessment": {
                "overall_risk": "unknown",
                "confidence_score": 0.0,
                "vulnerabilities": [],
                "security_features": [],
                "recommendations": ["Analysis failed - manual review required"]
            },
            "malware_analysis": [],
            "analysis_metadata": {
                "sensitivity_level": sensitivity,
                "total_vulnerabilities": 0,
                "total_malware_indicators": 0,
                "analysis_timestamp": "2025-01-27T12:00:00Z"
            }
        }

def detect_malware_patterns(binary_data: bytes) -> List[Dict[str, Any]]:
    """Detect malware patterns in binary data"""
    try:
        analyzer = BinaryAnalyzer()
        results = analyzer.detect_malware_patterns(binary_data)
        
        return [
            {
                "type": result.pattern_type,
                "confidence": result.confidence,
                "description": result.description,
                "severity": result.severity,
                "recommendations": result.recommendations
            } for result in results
        ]
        
    except Exception as e:
        return [{
            "type": "error",
            "confidence": 0.0,
            "description": f"Pattern detection failed: {str(e)}",
            "severity": "unknown",
            "recommendations": ["Manual analysis required"]
        }]

def assess_vulnerabilities(binary_data: bytes) -> Dict[str, Any]:
    """Assess vulnerabilities in binary data"""
    try:
        analyzer = BinaryAnalyzer()
        security_assessment = analyzer.analyze_binary_security(binary_data)
        
        return {
            "overall_risk": security_assessment.overall_risk,
            "confidence_score": security_assessment.confidence_score,
            "vulnerabilities": [
                {
                    "type": v.pattern_type,
                    "confidence": v.confidence,
                    "description": v.description,
                    "severity": v.severity,
                    "recommendations": v.recommendations
                } for v in security_assessment.vulnerabilities
            ],
            "security_features": security_assessment.security_features,
            "recommendations": security_assessment.recommendations
        }
        
    except Exception as e:
        return {
            "overall_risk": "unknown",
            "confidence_score": 0.0,
            "vulnerabilities": [],
            "security_features": [],
            "recommendations": [f"Assessment failed: {str(e)}"]
        }

if __name__ == "__main__":
    # Example usage
    print("Advanced Reverse Engineering Analysis Skill")
    print("This Skill provides specialized binary analysis capabilities")
    print("Use with EmberScale for comprehensive reverse engineering workflows")
