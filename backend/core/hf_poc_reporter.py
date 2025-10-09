"""LLM-powered POC report generator for vulnerability modules.
Supports both Hugging Face API and local LM Studio models."""

import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class HFPocReporter:
    """Generate detailed POC exploitation reports using LLM models."""
    
    def __init__(self):
        """Initialize the POC reporter with support for multiple backends."""
        # Check for LM Studio configuration first
        self.lm_studio_url = os.getenv('LM_STUDIO_API_URL', 'http://localhost:1234/v1')
        self.use_lm_studio = os.getenv('USE_LM_STUDIO', 'true').lower() == 'true'
        
        # Fallback to Hugging Face if not using LM Studio
        self.hf_api_key = os.getenv('HUGGINGFACE_API_KEY')
        self.hf_api_url_template = "https://api-inference.huggingface.co/models/{model_id}"
        
        # Custom model configuration
        self.custom_model = os.getenv('CUSTOM_MODEL_NAME', 'DeepSeek-R1-Distill-Qwen-7B-Uncensored')
        
        # Determine which backend is available
        if self.use_lm_studio:
            self.initialized = self._check_lm_studio_connection()
            if self.initialized:
                logger.info(f"Using LM Studio at {self.lm_studio_url}")
            else:
                logger.warning(f"LM Studio not available at {self.lm_studio_url}")
        else:
            self.initialized = self.hf_api_key is not None
            if not self.initialized:
                logger.warning("Neither LM Studio nor Hugging Face API configured.")
    
    
    def _check_lm_studio_connection(self) -> bool:
        """Check if LM Studio is running and accessible."""
        try:
            # Try to get models list from LM Studio
            response = requests.get(f"{self.lm_studio_url}/models", timeout=2)
            if response.status_code == 200:
                models = response.json()
                if models.get('data'):
                    logger.info(f"LM Studio connected. Available models: {[m['id'] for m in models['data']]}")
                return True
        except Exception as e:
            logger.debug(f"LM Studio connection check failed: {e}")
        return False
    
    async def generate_poc_report(
        self,
        target: str,
        module_name: str,
        scan_result: Dict[str, Any],
        model_id: str = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a detailed POC exploitation report for a single module's findings.
        
        Args:
            target: The target URL/system that was scanned
            module_name: Name of the scanner module (e.g., 'xss_scanner')
            scan_result: Dictionary containing the module's scan results
            model_id: Model ID to use (for HF) or model name (for LM Studio)
            params: Optional parameters for generation (temperature, max_new_tokens, etc.)
            
        Returns:
            Dictionary containing the POC report and metadata
        """
        if not self.initialized:
            return {
                "error": "POC generation unavailable. Please configure LM Studio or Hugging Face API.",
                "generated": False,
                "backend": "none"
            }
        
        try:
            # Extract vulnerabilities from scan result
            vulnerabilities = scan_result.get('vulnerabilities', [])
            
            if not vulnerabilities:
                return {
                    "message": "No vulnerabilities found to generate POC for.",
                    "generated": False
                }
            
            # Create exploitation-focused prompt for uncensored model
            prompt = self._create_exploitation_prompt(
                target, module_name, vulnerabilities, scan_result
            )
            
            # Set default generation parameters
            if params is None:
                params = {}
            
            # Use custom model if not specified
            if model_id is None:
                model_id = self.custom_model
            
            # Generate based on backend
            if self.use_lm_studio:
                generated_text, used_model = await self._generate_with_lm_studio(prompt, model_id, params)
                backend = "lm_studio"
            else:
                generated_text, used_model = await self._generate_with_huggingface(prompt, model_id, params)
                backend = "huggingface"
            
            if generated_text is None:
                return {
                    "error": "Failed to generate POC report",
                    "generated": False,
                    "backend": backend
                }
            
            # Parse the generated POC into structured format
            structured_poc = self._parse_poc_response(generated_text)
            
            return {
                "success": True,
                "generated": True,
                "model": used_model,
                "backend": backend,
                "generated_at": datetime.utcnow().isoformat(),
                "target": target,
                "module": module_name,
                "vulnerabilities_count": len(vulnerabilities),
                "report_text": generated_text,
                "structured_poc": structured_poc,
                "metadata": {
                    "generation_params": params,
                    "prompt_length": len(prompt)
                }
            }
            
        except Exception as e:
            logger.error(f"POC generation failed: {e}")
            return {
                "error": f"POC generation failed: {str(e)}",
                "generated": False
            }
    
    async def _generate_with_lm_studio(self, prompt: str, model_id: str, params: Dict[str, Any]) -> tuple[str, str]:
        """Generate text using LM Studio's OpenAI-compatible API."""
        try:
            # LM Studio uses OpenAI-compatible format
            headers = {
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model_id,  # LM Studio will use the loaded model
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a penetration testing expert. Generate detailed technical exploitation reports."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": params.get("temperature", 0.3),
                "max_tokens": params.get("max_new_tokens", 1500),
                "top_p": params.get("top_p", 0.95),
                "stream": False
            }
            
            response = requests.post(
                f"{self.lm_studio_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=120  # Longer timeout for local generation
            )
            
            if response.status_code == 200:
                result = response.json()
                generated_text = result['choices'][0]['message']['content']
                used_model = result.get('model', model_id)
                logger.info(f"LM Studio generation successful with model: {used_model}")
                return generated_text, used_model
            else:
                logger.error(f"LM Studio API error: {response.status_code} - {response.text}")
                return None, None
                
        except Exception as e:
            logger.error(f"LM Studio generation failed: {e}")
            return None, None
    
    async def _generate_with_huggingface(self, prompt: str, model_id: str, params: Dict[str, Any]) -> tuple[str, str]:
        """Generate text using Hugging Face API."""
        try:
            generation_params = {
                "max_new_tokens": params.get("max_new_tokens", 1500),
                "temperature": params.get("temperature", 0.3),
                "top_p": params.get("top_p", 0.95),
                "do_sample": True,
                "return_full_text": False
            }
            
            api_url = self.hf_api_url_template.format(model_id=model_id)
            headers = {
                "Authorization": f"Bearer {self.hf_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "inputs": prompt,
                "parameters": generation_params
            }
            
            response = requests.post(api_url, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                
                # Handle different response formats
                if isinstance(result, list) and len(result) > 0:
                    generated_text = result[0].get('generated_text', '')
                elif isinstance(result, dict):
                    generated_text = result.get('generated_text', '')
                else:
                    generated_text = str(result)
                
                logger.info(f"Hugging Face generation successful with model: {model_id}")
                return generated_text, model_id
            else:
                logger.error(f"HF API error: {response.status_code} - {response.text}")
                return None, None
                
        except Exception as e:
            logger.error(f"Hugging Face generation failed: {e}")
            return None, None
    
    def _create_exploitation_prompt(
        self,
        target: str,
        module_name: str,
        vulnerabilities: List[Dict[str, Any]],
        scan_result: Dict[str, Any]
    ) -> str:
        """Create an exploitation-focused prompt for the uncensored model."""
        
        # Format vulnerability details
        vuln_details = []
        for vuln in vulnerabilities[:5]:  # Limit to top 5 vulnerabilities
            vuln_info = f"""
Vulnerability: {vuln.get('name', 'Unknown')}
Severity: {vuln.get('severity', 'Unknown')}
Description: {vuln.get('description', 'No description')}
Affected URLs: {', '.join(vuln.get('affected_urls', [])[:3])}
Evidence: {json.dumps(vuln.get('evidence', {}), indent=2)[:500]}
"""
            vuln_details.append(vuln_info)
        
        vulnerabilities_text = "\n".join(vuln_details)
        
        # Create exploitation-focused prompt for uncensored model
        prompt = f"""You are a penetration testing expert creating a detailed Proof of Concept (POC) exploitation report. Generate a comprehensive technical POC that demonstrates how to exploit the discovered vulnerabilities.

TARGET SYSTEM: {target}
SCANNER MODULE: {module_name}
SCAN TIMESTAMP: {scan_result.get('completed_at', 'Unknown')}

DISCOVERED VULNERABILITIES:
{vulnerabilities_text}

Generate a DETAILED EXPLOITATION POC REPORT with the following sections:

1. EXECUTIVE SUMMARY
   - Brief overview of exploitable vulnerabilities
   - Risk rating and potential impact
   - Attack complexity assessment

2. TECHNICAL EXPLOITATION DETAILS
   For each vulnerability, provide:
   - Exact attack vectors and entry points
   - Step-by-step exploitation procedure
   - Specific payloads and injection points
   - Required tools and scripts
   - Expected responses and indicators of success

3. PROOF OF CONCEPT CODE
   - Working exploit code/scripts
   - Exact commands to execute
   - Payload variations for different scenarios
   - Bypass techniques for common defenses

4. ATTACK SCENARIOS
   - Real-world attack chains
   - Privilege escalation paths
   - Data exfiltration methods
   - Persistence mechanisms

5. IMPACT DEMONSTRATION
   - What data can be accessed/modified
   - System compromise possibilities
   - Business impact scenarios
   - Potential for lateral movement

6. DETECTION EVASION
   - Techniques to avoid detection
   - Log manipulation methods
   - WAF/IDS bypass strategies

7. REMEDIATION VERIFICATION
   - How to verify the vulnerability
   - Testing methodology
   - False positive indicators

8. TECHNICAL RECOMMENDATIONS
   - Specific code fixes
   - Configuration changes
   - Security controls to implement
   - Monitoring and detection rules

Provide actual working exploits, specific payloads, and technical details that a penetration tester would need to reproduce and validate these vulnerabilities. Be thorough and technical in your exploitation methodology."""
        
        return prompt
    
    def _parse_poc_response(self, generated_text: str) -> Dict[str, Any]:
        """Parse the generated POC text into structured sections."""
        
        sections = {
            "executive_summary": "",
            "exploitation_details": "",
            "poc_code": "",
            "attack_scenarios": "",
            "impact_demonstration": "",
            "detection_evasion": "",
            "remediation_verification": "",
            "technical_recommendations": "",
            "raw_text": generated_text
        }
        
        try:
            # Parse sections based on headers
            current_section = None
            current_content = []
            
            lines = generated_text.split('\n')
            
            for line in lines:
                line_upper = line.upper().strip()
                
                # Detect section headers
                if 'EXECUTIVE SUMMARY' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'executive_summary'
                    current_content = []
                elif 'EXPLOITATION DETAIL' in line_upper or 'TECHNICAL EXPLOITATION' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'exploitation_details'
                    current_content = []
                elif 'PROOF OF CONCEPT' in line_upper or 'POC CODE' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'poc_code'
                    current_content = []
                elif 'ATTACK SCENARIO' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'attack_scenarios'
                    current_content = []
                elif 'IMPACT DEMONSTRATION' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'impact_demonstration'
                    current_content = []
                elif 'DETECTION EVASION' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'detection_evasion'
                    current_content = []
                elif 'REMEDIATION VERIFICATION' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'remediation_verification'
                    current_content = []
                elif 'TECHNICAL RECOMMENDATION' in line_upper:
                    if current_section:
                        sections[current_section] = '\n'.join(current_content).strip()
                    current_section = 'technical_recommendations'
                    current_content = []
                elif current_section and line.strip():
                    current_content.append(line)
            
            # Save last section
            if current_section and current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            
            # Extract specific elements
            sections['payloads'] = self._extract_payloads(generated_text)
            sections['commands'] = self._extract_commands(generated_text)
            sections['risk_level'] = self._extract_risk_level(generated_text)
            
        except Exception as e:
            logger.error(f"Failed to parse POC response: {e}")
            sections['parse_error'] = str(e)
        
        return sections
    
    def _extract_payloads(self, text: str) -> List[str]:
        """Extract potential payloads from the generated text."""
        payloads = []
        lines = text.split('\n')
        
        for line in lines:
            # Look for common payload patterns
            if any(pattern in line for pattern in ['<script>', 'javascript:', 'onerror=', 'onclick=', 
                                                   'SELECT', 'UNION', '../', '%00', '{{', '${',
                                                   'cmd=', 'exec(', 'system(', 'eval(']):
                # Clean and add payload
                payload = line.strip()
                if payload and len(payload) < 500:  # Reasonable length limit
                    payloads.append(payload)
        
        return payloads[:20]  # Limit to 20 payloads
    
    def _extract_commands(self, text: str) -> List[str]:
        """Extract command lines and code snippets."""
        commands = []
        lines = text.split('\n')
        
        for i, line in enumerate(lines):
            # Look for command indicators
            if any(indicator in line for indicator in ['$', '#', '>', 'curl', 'wget', 'python', 
                                                       'node', 'php', 'bash', 'powershell']):
                command = line.strip()
                if command.startswith(('$', '#', '>')):
                    command = command[1:].strip()
                if command and len(command) < 300:
                    commands.append(command)
        
        return commands[:15]  # Limit to 15 commands
    
    def _extract_risk_level(self, text: str) -> str:
        """Extract the risk level from the generated text."""
        text_upper = text.upper()
        
        if 'CRITICAL' in text_upper:
            return 'CRITICAL'
        elif 'HIGH' in text_upper:
            return 'HIGH'
        elif 'MEDIUM' in text_upper:
            return 'MEDIUM'
        elif 'LOW' in text_upper:
            return 'LOW'
        else:
            return 'UNKNOWN'

# Singleton instance
hf_poc_reporter = HFPocReporter()
