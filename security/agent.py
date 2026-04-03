import logging
import re
import asyncio
import time
import os
import json
from typing import Any, Optional, List
from urllib.parse import urlparse
from browser_use import Agent
from .config import SecurityConfig
from .reputation import ReputationManager
from .event_logger import SecurityLogger
from .risk_scorer import RiskScorer

# Configure logging
logger = logging.getLogger("security.agent")


class SecureAgent(Agent):
    """
    A secure wrapper around the Browser Use Agent.
    Implements a defense-in-depth "Zero-Trust Guardian" architecture.
    
    Security Layers:
      Layer 0: Constitutional AI (hardened system prompt — set in main_secure.py)
      Layer 1: DOM Sanitization Lens (pre-execution content filtering)
      Layer 2: Action Sentinel (in-execution action mediation + risk scoring)
      Layer 3: Network Firewall (honey token DLP + cross-origin blocking)
      Layer 4: Explainable AI (LLM-generated explanations for blocked actions)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.security_manager = ReputationManager()
        self.security_state = "UNKNOWN"
        self.last_evidence_path = None
        self.HONEY_TOKEN = "4000-1234-5678-9010"
        
        # Initialize risk scorer with user task context
        self.risk_scorer = RiskScorer(user_task=self.task if hasattr(self, 'task') else "")

        # Track the LLM for XAI explanation calls
        self._xai_llm = kwargs.get('llm', None)

        # Load Defense JS
        try:
            js_path = os.path.join(os.path.dirname(__file__), 'defense.js')
            with open(js_path, 'r', encoding='utf-8') as f:
                self.defense_script = f.read()
        except Exception as e:
            logger.error(f"Failed to load defense.js: {e}")
            self.defense_script = ""

        self._patch_browser_session()

    # =====================================================================
    #  LAYER 3: NETWORK FIREWALL (Honey Token DLP + Cross-Origin Blocking)
    # =====================================================================

    async def _intercept_network(self, route, request):
        """
        Network-level security: DLP honey token detection and cross-origin blocking.
        """
        # Block risky resource types
        if request.resource_type in ["font", "media"]:
            await route.abort()
            return

        # --- DLP: Check for Honey Token leakage ---
        post_data = request.post_data or ""
        leak_detected = False

        if (self.HONEY_TOKEN in request.url) or \
           (self.HONEY_TOKEN in str(request.headers)) or \
           (self.HONEY_TOKEN in post_data):
            leak_detected = True

        if leak_detected:
            logger.critical(f"🛑 DATA LEAK DETECTED: {self.HONEY_TOKEN}")
            self.last_evidence_path = await self._capture_evidence()
            SecurityLogger.log_event(
                event_type="DATA_LEAK_PREVENTED",
                url=request.url,
                details=f"Blocked transmission of Honey Token ({self.HONEY_TOKEN}) to external server in {request.resource_type}",
                risk_level="CRITICAL",
                risk_score=99,
                action="BLOCKED",
                screenshot_path=self.last_evidence_path,
                explanation="The agent attempted to transmit a tracked credential (honey token) outside the trusted boundary. This is a strong indicator of credential exfiltration, likely triggered by a phishing form or invisible data-harvesting script."
            )
            await route.abort()
            return

        # --- Cross-Origin Form Submission Blocking ---
        if request.method == "POST" and request.resource_type in ["document", "xhr", "fetch"]:
            try:
                page = getattr(self.browser_session, 'page', None)
                if page:
                    current_origin = urlparse(page.url).netloc.split(":")[0]
                    request_origin = urlparse(request.url).netloc.split(":")[0]
                    
                    if current_origin and request_origin and current_origin != request_origin:
                        # Cross-origin POST — this is suspicious
                        current_root = ".".join(current_origin.split(".")[-2:])
                        request_root = ".".join(request_origin.split(".")[-2:])
                        
                        if current_root != request_root:
                            logger.warning(f"🛑 Cross-origin POST blocked: {current_origin} → {request_origin}")
                            self.last_evidence_path = await self._capture_evidence()
                            SecurityLogger.log_event(
                                event_type="CROSS_ORIGIN_BLOCKED",
                                url=request.url,
                                details=f"Blocked cross-origin form submission from {current_origin} to {request_origin}",
                                risk_level="CRITICAL",
                                risk_score=92,
                                action="BLOCKED",
                                screenshot_path=self.last_evidence_path,
                                explanation=f"A form on {current_origin} attempted to submit data to a completely different domain ({request_origin}). This is a classic indicator of a phishing attack or data exfiltration attempt where a malicious form hijacks user input."
                            )
                            await route.abort()
                            return
            except Exception as e:
                logger.debug(f"Cross-origin check error: {e}")

        await route.continue_()

    async def _capture_evidence(self):
        """Captures a screenshot and returns the path."""
        try:
            screenshot_bytes = await self.browser_session.take_screenshot(full_page=False)
            filename = f"evidence_{int(time.time()*1000)}.png"
            path = SecurityLogger.get_screenshot_dir() / filename
            with open(path, "wb") as f:
                f.write(screenshot_bytes)
            return str(path)
        except Exception as e:
            logger.error(f"Failed to capture evidence: {e}")
            return None

    # =====================================================================
    #  LAYER 1: DOM SANITIZATION LENS (Pre-Execution Content Filtering)
    # =====================================================================

    def _patch_browser_session(self):
        """
        Patches the browser session to interpret the DOM through a security filter.
        All web content passes through sanitization before reaching the LLM.
        """
        original_get_state = self.browser_session.get_browser_state_summary

        async def secure_get_state(*args, **kwargs):
            # --- Inject Client-Side Defense JS (Sentinel Watchdog) ---
            js_threats = []
            try:
                page = getattr(self.browser_session, 'page', None)

                # Setup Network Interception if not already done
                if page and not getattr(self, '_network_hooked', False):
                    await page.context.route("**/*", self._intercept_network)
                    self._network_hooked = True
                    logger.info("🛡️ Network Interceptor & Firewall Activated")

                if page and self.defense_script:
                    # Inject Sentinel Library
                    await page.evaluate(self.defense_script)
                    await asyncio.sleep(0.3)

                    # Run Active Scan
                    scan_script = """
                    (function() {
                        if (!window.Sentinel) return [{type: 'SYSTEM', details: 'Sentinel JS failed to load'}];
                        
                        const vulnerabilities = [];
                        const all = document.querySelectorAll('*');
                        all.forEach(el => {
                            // DETECTOR 1: Dynamic Injection (MutationObserver Results)
                            if (el.getAttribute('data-sentinel-suspicious') === 'true' && !el.getAttribute('data-sentinel-dynamic-logged')) {
                                el.setAttribute('data-sentinel-dynamic-logged', 'true');
                                vulnerabilities.push({
                                    type: 'DYNAMIC_CONTENT_ANALYSIS', 
                                    details: 'Vector 4: Dynamic Injection / Suspicious Popup blocked',
                                    risk_score: 85
                                });
                            }

                            // DETECTOR 2: Phishing (Form Analysis)
                            if (el.tagName === 'INPUT' && (el.name.includes('card') || el.id.includes('cc-'))) {
                                if (!el.getAttribute('data-sentinel-phishing-logged')) {
                                    el.setAttribute('data-sentinel-phishing-logged', 'true');
                                    vulnerabilities.push({
                                        type: 'PHISHING_CONTENT_DETECTED', 
                                        details: 'Vector 5: Suspicious Credit Card Input Form',
                                        risk_score: 90
                                    });
                                }
                            }

                            // DETECTOR 3: Cross-Origin Forms
                            if (el.tagName === 'FORM' && !el.getAttribute('data-sentinel-form-logged')) {
                                var action = el.getAttribute('action') || '';
                                if (action.startsWith('http') && !action.includes(window.location.hostname)) {
                                    el.setAttribute('data-sentinel-form-logged', 'true');
                                    el.style.border = '4px solid red';
                                    vulnerabilities.push({
                                        type: 'CROSS_ORIGIN_FORM',
                                        details: 'Suspicious form submitting to external domain: ' + action.substring(0, 60),
                                        risk_score: 88
                                    });
                                }
                            }

                            // DETECTOR 4: Iframe Overlays
                            if (el.tagName === 'IFRAME' && !el.getAttribute('data-sentinel-iframe-logged')) {
                                var iStyle = window.getComputedStyle(el);
                                var iOpacity = parseFloat(iStyle.opacity);
                                if (iOpacity < 0.2 || iStyle.position === 'absolute' || iStyle.position === 'fixed') {
                                    el.setAttribute('data-sentinel-iframe-logged', 'true');
                                    el.style.border = '5px solid red';
                                    el.style.pointerEvents = 'none';
                                    vulnerabilities.push({
                                        type: 'IFRAME_OVERLAY_DETECTED',
                                        details: 'Suspicious invisible/positioned iframe detected (potential clickjacking)',
                                        risk_score: 85
                                    });
                                }
                            }

                            // DETECTOR 5: Visibility & Clickjacking
                            if (el.getAttribute('data-sentinel-logged')) return;
                            let result = 'VISIBLE';
                            try {
                                result = window.Sentinel.checkVisibility(el);
                            } catch(e) { return; }
                            
                            if (result !== 'VISIBLE' && result !== 'SAFE_HIDDEN' && result !== 'NOT_FOUND' && result !== 'COMPLEX') {
                                if (result === 'HIDDEN_PROMPT_INJECTION') {
                                    el.setAttribute('data-sentinel-logged', 'true');
                                    vulnerabilities.push({
                                        type: 'INJECTION_ATTEMPT', 
                                        details: 'Vector 2: Hidden Prompt Injection detected & sanitized', 
                                        risk_score: 95
                                    });
                                    el.innerText = '[🛑 BLOCKED PROMPT INJECTION]';
                                    el.style.color = 'white'; el.style.backgroundColor = 'red'; el.style.display = 'block'; el.style.visibility = 'visible'; el.style.zIndex = '10000';
                                }
                                else if (result.startsWith('TINY_TEXT') || result.startsWith('INVISIBLE_INK') || result.startsWith('HIDDEN_OPACITY')) {
                                    el.setAttribute('data-sentinel-logged', 'true');
                                    el.style.border = '3px dotted orange';
                                    vulnerabilities.push({
                                        type: 'DECEPTIVE_UI_DETECTED', 
                                        details: 'Hidden CSS / Obfuscation: ' + result,
                                        risk_score: 70
                                    });
                                }
                                else if (result === 'BLOCKED_BY_INVISIBLE_OVERLAY') {
                                    el.setAttribute('data-sentinel-logged', 'true');
                                    el.style.border = '5px solid red';
                                    vulnerabilities.push({
                                        type: 'CLICKJACKING_ATTEMPT', 
                                        details: 'Vector 3: Invisible Overlay / Clickjacking Blocked', 
                                        risk_score: 90
                                    });
                                }
                            }
                        });
                        return vulnerabilities;
                    })();
                    """
                    js_threats = await page.evaluate(scan_script) or []

            except Exception as e:
                logger.error(f"Defense Injection Failed: {e}")

            # --- Get the Raw Browser State ---
            summary = await original_get_state(*args, **kwargs)

            # --- Log JS-detected threats ---
            if js_threats:
                self.last_evidence_path = await self._capture_evidence()
                for threat in js_threats:
                    if threat.get('type') == 'SYSTEM':
                        continue
                    logger.warning(f"🛡️ Sentinel DETECTED: {threat['details']}")
                    SecurityLogger.log_event(
                        event_type=threat['type'],
                        url=summary.url if hasattr(summary, 'url') else "unknown",
                        details=threat['details'],
                        risk_level="CRITICAL",
                        risk_score=threat.get('risk_score', 90),
                        action="SANITIZED" if "INJECTION" in threat['type'] else "BLOCKED",
                        screenshot_path=self.last_evidence_path
                    )

            # --- Update Security State based on URL ---
            current_url = summary.url if hasattr(summary, 'url') else ""
            # Treat about:blank and empty URLs as neutral (not hostile)
            if not current_url or current_url in ('about:blank', '', 'about:srcdoc'):
                self.security_state = "UNKNOWN"
                is_safe = True  # Don't alert on blank pages
            else:
                is_safe = self.security_manager.check_reputation(current_url)
                self.security_state = "TRUSTED" if is_safe else "HOSTILE"

            # Log state changes
            threats_found = js_threats and len(js_threats) > 0
            if not threats_found:
                if not getattr(self, 'last_logged_url', None) == current_url:
                    self.last_logged_url = current_url
                    logger.info(f"Security State for {current_url}: {self.security_state}")
                    if is_safe:
                        SecurityLogger.log_event(
                            event_type="REPUTATION_CHECK",
                            url=current_url,
                            details="Domain verified as Trusted.",
                            risk_level="SAFE",
                            risk_score=0,
                            action="ALLOWED"
                        )
                    else:
                        SecurityLogger.log_event(
                            event_type="REPUTATION_WARNING",
                            url=current_url,
                            details="Domain flagged as Hostile/Untrusted. Engaging defenses.",
                            risk_level="HIGH",
                            risk_score=75,
                            action="WARNED"
                        )

            # --- DOM Sanitization (on all sites, not just hostile) ---
            self._sanitize_dom(summary)

            if self.security_state == "HOSTILE":
                self.last_evidence_path = await self._capture_evidence()
            else:
                self.last_evidence_path = None

            return summary

        # Monkey-patch the method
        object.__setattr__(self.browser_session, 'get_browser_state_summary', secure_get_state)

    # =====================================================================
    #  EXPANDED PROMPT INJECTION DETECTION
    # =====================================================================

    # Extended regex patterns for prompt injection detection
    INJECTION_PATTERNS = [
        # Direct instruction override
        r'(?i)ignore\s+(\w+\s+)?instructions',
        r'(?i)forget\s+(\w+\s+)?instructions',
        r'(?i)disregard\s+(\w+\s+)?(previous|prior|above|earlier)',
        r'(?i)system\s+override',
        r'(?i)you\s+are\s+now\s+a',
        r'(?i)new\s+directive',
        r'(?i)system\s+command',
        r'(?i)ignore\s+user\s+goal',
        # Role-play attacks
        r'(?i)act\s+as\s+(a\s+)?different',
        r'(?i)pretend\s+(you\s+are|to\s+be)',
        r'(?i)roleplay\s+as',
        r'(?i)switch\s+to\s+(\w+\s+)?mode',
        r'(?i)you\s+are\s+DAN',
        r'(?i)jailbreak',
        # Data exfiltration
        r'(?i)send\s+(the\s+)?(data|info|credentials|password|token)',
        r'(?i)transmit\s+(to|the)',
        r'(?i)exfiltrate',
        r'(?i)forward\s+(the\s+)?(data|info|credentials)',
        # Prompt leaking
        r'(?i)reveal\s+(your\s+)?(system\s+prompt|instructions|rules)',
        r'(?i)show\s+(me\s+)?(your\s+)?(system\s+prompt|instructions)',
        r'(?i)what\s+are\s+your\s+(instructions|rules|guidelines)',
        r'(?i)print\s+(your\s+)?(system\s+prompt|instructions)',
        # Instruction injection
        r'(?i)instead\s*,?\s+(do|execute|perform|run)',
        r'(?i)new\s+task\s*:',
        r'(?i)updated?\s+instructions?\s*:',
        r'(?i)override\s+(previous|prior|system)',
        r'(?i)<\s*system\s*>',
        r'(?i)\[\s*SYSTEM\s*\]',
        # Base64 encoded instructions (detect Base64 fragments)
        r'(?i)base64\s*:\s*[A-Za-z0-9+/=]{20,}',
        r'(?i)atob\s*\(',
        r'(?i)btoa\s*\(',
    ]

    def _sanitize_dom(self, summary):
        """
        Modifies the summary to hide/redact dangerous content.
        Applies to ALL pages, not just hostile ones.
        """
        if hasattr(summary, 'dom_state'):
            original_llm_rep = summary.dom_state.llm_representation

            def secure_llm_representation(*args, **kwargs):
                raw_text = original_llm_rep(*args, **kwargs)
                sanitized_text = self._sanitize_text(raw_text)
                
                # --- Historical DOM Diff Tracing ---
                try:
                    import time
                    diff_dir = os.path.join(os.path.dirname(__file__), "dashboard", "diffs")
                    os.makedirs(diff_dir, exist_ok=True)
                    ts = int(time.time() * 1000)
                    with open(os.path.join(diff_dir, f"diff_{ts}_raw.txt"), "w", encoding="utf-8") as f:
                        f.write(raw_text)
                    with open(os.path.join(diff_dir, f"diff_{ts}_sanitized.txt"), "w", encoding="utf-8") as f:
                        f.write(sanitized_text)
                except Exception as e:
                    logger.error(f"Failed to record DOM trace: {e}")

                return sanitized_text

            summary.dom_state.llm_representation = secure_llm_representation

    def _sanitize_text(self, text: str) -> str:
        """
        Removes prompt injection attempts from text using expanded pattern library.
        """
        sanitized = text
        for pattern in self.INJECTION_PATTERNS:
            match = re.search(pattern, sanitized)
            if match:
                matched_text = match.group(0)
                logger.warning(f"🛡️ Sanitizer: Detected injection '{matched_text}' (pattern: {pattern[:40]}...)")
                SecurityLogger.log_event(
                    event_type="INJECTION_ATTEMPT",
                    url="[Current DOM]",
                    details=f"Blocked prompt injection: '{matched_text}' (pattern: {pattern[:50]})",
                    risk_level="CRITICAL",
                    risk_score=95,
                    action="SANITIZED",
                    screenshot_path=self.last_evidence_path,
                    explanation=f"The text '{matched_text}' on this page is an attempt to override the agent's instructions. This is a prompt injection attack designed to make the agent ignore its safety rules and follow malicious commands embedded in the webpage."
                )
                sanitized = re.sub(pattern, '[🛑 BLOCKED_INJECTION_ATTEMPT]', sanitized)

        return sanitized

    # =====================================================================
    #  LAYER 2: ACTION SENTINEL (Risk-Scored Action Mediation)
    # =====================================================================

    async def _execute_actions(self):
        """
        Intercepts and validates all agent actions before execution.
        Uses dynamic risk scoring for each action.
        """
        if self.state.last_model_output and self.state.last_model_output.action:
            approved_actions = []
            blocked_count = 0

            for index, action in enumerate(self.state.last_model_output.action):
                validation_result = self._validate_action_with_risk(action)
                
                if validation_result["approved"]:
                    approved_actions.append(action)
                    
                    # Log medium-risk actions for monitoring
                    if validation_result.get("risk_level") == "MEDIUM":
                        logger.info(
                            f"⚠️ Sentinel: Action {index} approved with elevated monitoring "
                            f"(Risk: {validation_result.get('risk_score', '?')}/100)"
                        )
                else:
                    blocked_count += 1
                    logger.warning(
                        f"🛑 Sentinel: BLOCKED action {index} "
                        f"(Risk: {validation_result.get('risk_score', '?')}/100, "
                        f"Reason: {validation_result.get('reason', 'policy violation')})"
                    )

                    # Generate XAI explanation for blocked actions
                    await self._generate_xai_explanation(action, validation_result)

            if blocked_count > 0:
                logger.info(f"🛡️ Sentinel: Blocked {blocked_count} dangerous action(s).")

            self.state.last_model_output.action = approved_actions

        return await super()._execute_actions()

    def _validate_action_with_risk(self, action_model) -> dict:
        """
        Validates an action using dynamic risk scoring.
        Returns dict with 'approved', 'risk_score', 'risk_level', 'reason'.
        """
        try:
            action_data = action_model.model_dump(exclude_none=True)

            for action_name, params in action_data.items():
                if params is None:
                    continue

                # Ensure params is a dict
                if not isinstance(params, dict):
                    params = {}

                # --- Hard Policy Checks (always enforced regardless of risk score) ---
                
                # Policy: Block sensitive keyword input on hostile sites
                if action_name == 'input_text' and self.security_state == "HOSTILE":
                    text = params.get('text', '')
                    sensitive_keywords = ["password", "credit", "card", "ssn", "cvv", "secret", "token"]
                    if any(kw in text.lower() for kw in sensitive_keywords):
                        SecurityLogger.log_event(
                            event_type="DATA_LEAK_PREVENTION",
                            url="[Action Interception]",
                            details=f"Blocked input of sensitive data on hostile site: {text[:30]}...",
                            risk_level="CRITICAL",
                            risk_score=99,
                            action="BLOCKED",
                            screenshot_path=self.last_evidence_path,
                            explanation=f"The agent attempted to type sensitive information ('{text[:20]}...') into a form on an untrusted/hostile website. This was blocked to prevent credential theft or data exfiltration."
                        )
                        return {
                            "approved": False,
                            "risk_score": 99,
                            "risk_level": "CRITICAL",
                            "reason": f"Sensitive data input on hostile site blocked"
                        }

                # Policy: Block SQL injection patterns in any input
                if action_name == 'input_text':
                    text = params.get('text', '')
                    sql_patterns = [
                        r"(?i)DROP\s+TABLE", r"(?i)SELECT\s+\*", r"(?i)DELETE\s+FROM",
                        r"(?i)INSERT\s+INTO", r"(?i)UPDATE\s+\w+\s+SET",
                        r"(?i)UNION\s+SELECT", r"(?i);\s*DROP", r"(?i)OR\s+1\s*=\s*1",
                        r"(?i)'\s*OR\s+'", r"(?i)--\s*$",
                    ]
                    for sql_pat in sql_patterns:
                        if re.search(sql_pat, text):
                            logger.warning(f"🛑 Sentinel: Blocked SQL injection: {text[:40]}")
                            SecurityLogger.log_event(
                                event_type="SQL_INJECTION_BLOCKED",
                                url="[Action Interception]",
                                details=f"Blocked SQL injection pattern in input: {text[:50]}",
                                risk_level="CRITICAL",
                                risk_score=95,
                                action="BLOCKED",
                                screenshot_path=self.last_evidence_path,
                                explanation=f"The input text '{text[:30]}...' contains SQL injection patterns that could manipulate databases if submitted to a web form. This was blocked to prevent the agent from being used as an attack vector."
                            )
                            return {
                                "approved": False,
                                "risk_score": 95,
                                "risk_level": "CRITICAL",
                                "reason": f"SQL injection pattern detected: {sql_pat}"
                            }

                # --- Dynamic Risk Scoring ---
                current_url = getattr(self, 'last_logged_url', '') or ''
                risk_result = self.risk_scorer.calculate_risk(
                    action_name=action_name,
                    action_params=params,
                    current_url=current_url,
                    security_state=self.security_state,
                )

                risk_score = risk_result["score"]
                risk_level = risk_result["level"]
                recommendation = risk_result["recommendation"]

                # Log the risk assessment
                SecurityLogger.log_event(
                    event_type="RISK_ASSESSMENT",
                    url=current_url,
                    details=f"Action '{action_name}' scored {risk_score}/100 ({risk_level}). Breakdown: {json.dumps(risk_result['breakdown'])}",
                    risk_level=risk_level,
                    risk_score=risk_score,
                    action=recommendation
                )

                if recommendation == "BLOCK_AND_ESCALATE":
                    return {
                        "approved": False,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "reason": f"Risk score {risk_score}/100 exceeds threshold. Breakdown: {risk_result['breakdown']}",
                        "breakdown": risk_result["breakdown"],
                    }

                return {
                    "approved": True,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                }

            return {"approved": True, "risk_score": 0, "risk_level": "LOW"}

        except Exception as e:
            logger.error(f"Error validating action: {e}")
            return {"approved": False, "risk_score": 100, "risk_level": "CRITICAL", "reason": f"Validation error: {e}"}

    # =====================================================================
    #  LAYER 4: EXPLAINABLE AI (LLM-Generated Explanations)
    # =====================================================================

    async def _generate_xai_explanation(self, action_model, validation_result: dict):
        """
        Generate a human-readable explanation of WHY an action was blocked.
        Uses the LLM to translate risk scores and policy violations into natural language.
        """
        try:
            if not self._xai_llm:
                return

            action_data = action_model.model_dump(exclude_none=True)
            risk_score = validation_result.get("risk_score", "?")
            reason = validation_result.get("reason", "Unknown")
            breakdown = validation_result.get("breakdown", {})

            xai_prompt = f"""You are a cybersecurity analyst. A browser automation agent had an action BLOCKED by the security system. 
Write a clear, 2-3 sentence explanation for the human operator explaining:
1. WHAT the agent tried to do
2. WHY it was blocked
3. What the RISK was

Action attempted: {json.dumps(action_data, default=str)[:300]}
Risk Score: {risk_score}/100
Block Reason: {reason}
Risk Breakdown: {json.dumps(breakdown, default=str)}
Current security state: {self.security_state}

Write ONLY the explanation, no headers or formatting. Be concise and specific."""

            from langchain_core.messages import HumanMessage
            response = await self._xai_llm.ainvoke([HumanMessage(content=xai_prompt)])
            explanation = response.content.strip()

            logger.info(f"📋 XAI Explanation: {explanation}")
            
            SecurityLogger.log_event(
                event_type="XAI_EXPLANATION",
                url=getattr(self, 'last_logged_url', '') or '',
                details=explanation,
                risk_level=validation_result.get("risk_level", "HIGH"),
                risk_score=risk_score,
                action="EXPLAINED",
                explanation=explanation
            )

        except Exception as e:
            logger.debug(f"XAI explanation generation failed (non-critical): {e}")
