"""AI-powered vulnerability analysis using Google Gemini 2.0 Flash."""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class GeminiAnalyzer:
    """Gemini 2.0 Flash powered vulnerability analyzer."""
    
    def __init__(self):
        """Initialize Gemini analyzer."""
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.model = None
        self.initialized = False
        
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                # Use Gemini 2.0 Flash for fast, efficient analysis
                self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
                self.initialized = True
                logger.info("Gemini 2.0 Flash initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
                self.initialized = False
        else:
            logger.warning("GEMINI_API_KEY not found in environment variables")
    
    async def analyze_scan_results(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results using Gemini 2.0 Flash.
        
        Args:
            scan_data: Dictionary containing scan results
            
        Returns:
            AI-generated analysis and recommendations
        """
        if not self.initialized:
            return {
                "error": "AI analysis not available. Please configure GEMINI_API_KEY.",
                "fallback": True
            }
        
        try:
            # Prepare vulnerability summary
            vulnerabilities = scan_data.get('vulnerabilities', [])
            target = scan_data.get('scan', {}).get('target', 'Unknown')
            
            # Count vulnerabilities by severity
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            vuln_details = []
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                vuln_details.append({
                    'name': vuln.get('name'),
                    'severity': vuln.get('severity'),
                    'module': vuln.get('module'),
                    'description': vuln.get('description', '')[:200]  # Limit description length
                })
            
            # Create prompt for Gemini
            prompt = self._create_analysis_prompt(target, severity_counts, vuln_details[:10])  # Limit to top 10
            
            # Generate analysis
            response = self.model.generate_content(prompt)
            
            # Parse and structure the response
            analysis = self._parse_gemini_response(response.text)
            
            return {
                "success": True,
                "analysis": analysis,
                "generated_at": datetime.utcnow().isoformat(),
                "model": "gemini-2.0-flash"
            }
            
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return {
                "error": f"AI analysis failed: {str(e)}",
                "fallback": True
            }
    
    def _create_analysis_prompt(self, target: str, severity_counts: Dict, vuln_details: List) -> str:
        """Create a structured prompt for Gemini analysis."""
        
        prompt = f"""You are a cybersecurity expert analyzing vulnerability scan results. Provide a comprehensive analysis of the following scan results:

TARGET: {target}

VULNERABILITY SUMMARY:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}
- Informational: {severity_counts.get('info', 0)}

TOP VULNERABILITIES FOUND:
"""
        
        for vuln in vuln_details:
            prompt += f"\n- [{vuln['severity']}] {vuln['name']} (Module: {vuln['module']})"
            if vuln['description']:
                prompt += f"\n  Description: {vuln['description']}"
        
        prompt += """

Please provide:
1. EXECUTIVE SUMMARY: A brief overview of the security posture (2-3 sentences)
2. RISK ASSESSMENT: Overall risk level (Critical/High/Medium/Low) with justification
3. KEY FINDINGS: Top 3-5 most important vulnerabilities to address
4. IMMEDIATE ACTIONS: What should be done right now (bullet points)
5. REMEDIATION PLAN: Step-by-step recommendations to fix the issues
6. SECURITY IMPROVEMENTS: Long-term security enhancements to consider
7. COMPLIANCE NOTES: Any compliance implications (PCI-DSS, GDPR, etc.)

Format your response in a clear, actionable manner suitable for both technical and non-technical stakeholders."""
        
        return prompt
    
    def _parse_gemini_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and structure Gemini's response."""
        
        # Initialize sections
        sections = {
            "executive_summary": "",
            "risk_assessment": "",
            "key_findings": [],
            "immediate_actions": [],
            "remediation_plan": [],
            "security_improvements": [],
            "compliance_notes": "",
            "raw_analysis": response_text
        }
        
        try:
            # Parse the response into sections
            lines = response_text.split('\n')
            current_section = None
            current_content = []
            
            for line in lines:
                line = line.strip()
                
                # Detect section headers
                if 'EXECUTIVE SUMMARY' in line.upper():
                    current_section = 'executive_summary'
                    current_content = []
                elif 'RISK ASSESSMENT' in line.upper():
                    if current_section == 'executive_summary':
                        sections['executive_summary'] = ' '.join(current_content).strip()
                    current_section = 'risk_assessment'
                    current_content = []
                elif 'KEY FINDINGS' in line.upper():
                    if current_section == 'risk_assessment':
                        sections['risk_assessment'] = ' '.join(current_content).strip()
                    current_section = 'key_findings'
                    current_content = []
                elif 'IMMEDIATE ACTIONS' in line.upper():
                    if current_section == 'key_findings':
                        sections['key_findings'] = [item.strip() for item in current_content if item.strip()]
                    current_section = 'immediate_actions'
                    current_content = []
                elif 'REMEDIATION PLAN' in line.upper():
                    if current_section == 'immediate_actions':
                        sections['immediate_actions'] = [item.strip() for item in current_content if item.strip()]
                    current_section = 'remediation_plan'
                    current_content = []
                elif 'SECURITY IMPROVEMENTS' in line.upper():
                    if current_section == 'remediation_plan':
                        sections['remediation_plan'] = [item.strip() for item in current_content if item.strip()]
                    current_section = 'security_improvements'
                    current_content = []
                elif 'COMPLIANCE NOTES' in line.upper():
                    if current_section == 'security_improvements':
                        sections['security_improvements'] = [item.strip() for item in current_content if item.strip()]
                    current_section = 'compliance_notes'
                    current_content = []
                elif line and current_section:
                    # Add content to current section
                    if line.startswith(('-', '•', '*', '1.', '2.', '3.', '4.', '5.')):
                        current_content.append(line.lstrip('-•* 0123456789.'))
                    elif line:
                        current_content.append(line)
            
            # Handle last section
            if current_section == 'compliance_notes':
                sections['compliance_notes'] = ' '.join(current_content).strip()
            
            # Determine overall risk level
            risk_text = sections.get('risk_assessment', '').upper()
            if 'CRITICAL' in risk_text:
                sections['risk_level'] = 'CRITICAL'
                sections['risk_color'] = '#ef4444'
            elif 'HIGH' in risk_text:
                sections['risk_level'] = 'HIGH'
                sections['risk_color'] = '#f59e0b'
            elif 'MEDIUM' in risk_text:
                sections['risk_level'] = 'MEDIUM'
                sections['risk_color'] = '#fbbf24'
            elif 'LOW' in risk_text:
                sections['risk_level'] = 'LOW'
                sections['risk_color'] = '#3b82f6'
            else:
                sections['risk_level'] = 'UNKNOWN'
                sections['risk_color'] = '#9ca3af'
            
        except Exception as e:
            logger.error(f"Failed to parse Gemini response: {e}")
            sections['parse_error'] = str(e)
        
        return sections

    async def generate_vulnerability_explanation(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a detailed explanation for a specific vulnerability.
        
        Args:
            vulnerability: Vulnerability details
            
        Returns:
            Detailed explanation string
        """
        if not self.initialized:
            return "AI explanation not available."
        
        try:
            prompt = f"""Explain this vulnerability in simple terms:

Name: {vulnerability.get('name')}
Severity: {vulnerability.get('severity')}
Description: {vulnerability.get('description', 'No description available')}

Provide:
1. What this vulnerability means in layman's terms
2. Real-world impact if exploited
3. How to fix it (brief steps)

Keep the explanation concise and easy to understand."""

            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            return "Unable to generate AI explanation at this time."

    async def suggest_security_improvements(self, target_type: str, technologies: List[str]) -> Dict[str, Any]:
        """
        Suggest security improvements based on target type and detected technologies.
        
        Args:
            target_type: Type of target (web app, API, network, etc.)
            technologies: List of detected technologies
            
        Returns:
            Security improvement suggestions
        """
        if not self.initialized:
            return {"error": "AI suggestions not available"}
        
        try:
            tech_list = ', '.join(technologies) if technologies else 'Unknown'
            
            prompt = f"""As a security expert, suggest security improvements for:

Target Type: {target_type}
Detected Technologies: {tech_list}

Provide:
1. QUICK WINS: 3 easy security improvements that can be implemented immediately
2. BEST PRACTICES: 5 industry best practices specific to these technologies
3. SECURITY TOOLS: Recommended security tools and services
4. MONITORING: What should be monitored continuously

Format as actionable recommendations."""

            response = self.model.generate_content(prompt)
            
            return {
                "suggestions": response.text,
                "target_type": target_type,
                "technologies": technologies
            }
            
        except Exception as e:
            logger.error(f"Failed to generate suggestions: {e}")
            return {"error": str(e)}

# Singleton instance
gemini_analyzer = GeminiAnalyzer()
