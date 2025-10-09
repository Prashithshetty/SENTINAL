#!/usr/bin/env python3
"""
Sentinel Security Scanner - Professional CLI Interface
Advanced Vulnerability Assessment Framework
"""

import os
import sys
import asyncio
import json
import random
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any

# Add rich for beautiful CLI interface
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style
except ImportError:
    print("Installing required dependencies...")
    os.system(f"{sys.executable} -m pip install rich")
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import scanner modules
from backend.scanner.engine import scanner_engine
from backend.scanner.base_module import ScanType, ScanConfig
from backend.scanner.poc_generator import poc_generator
from backend.core.config import settings

# Initialize Rich console
console = Console()

# Professional ASCII Art Banners
MAIN_BANNER = """
[bold cyan]
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗                ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║                ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║                ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║                ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗           ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝           ║
║                                                                                ║
║              [bold white]Advanced Vulnerability Assessment Framework v2.0[/bold white]              ║
║                     [dim white]Professional Security Testing Suite[/dim white]                     ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
[/bold cyan]
"""

# ASCII Animation Frames
LOADING_FRAMES = [
    "[cyan]|[/cyan]", "[cyan]/[/cyan]", "[cyan]-[/cyan]", "[cyan]\\[/cyan]"
]

SCANNING_FRAMES = [
    """
    [cyan]
    ┌─────────────┐
    │ [>>        ]│
    └─────────────┘
    [/cyan]
    """,
    """
    [cyan]
    ┌─────────────┐
    │ [  >>      ]│
    └─────────────┘
    [/cyan]
    """,
    """
    [cyan]
    ┌─────────────┐
    │ [    >>    ]│
    └─────────────┘
    [/cyan]
    """,
    """
    [cyan]
    ┌─────────────┐
    │ [      >>  ]│
    └─────────────┘
    [/cyan]
    """,
    """
    [cyan]
    ┌─────────────┐
    │ [        >>]│
    └─────────────┘
    [/cyan]
    """
]

PULSE_FRAMES = [
    "[dim cyan]◉[/dim cyan]",
    "[cyan]◉[/cyan]",
    "[bold cyan]◉[/bold cyan]",
    "[cyan]◉[/cyan]"
]

WAVE_FRAMES = [
    "[cyan]~[/cyan]  [dim cyan]~[/dim cyan]  [dim cyan]~[/dim cyan]",
    "[dim cyan]~[/dim cyan]  [cyan]~[/cyan]  [dim cyan]~[/dim cyan]",
    "[dim cyan]~[/dim cyan]  [dim cyan]~[/dim cyan]  [cyan]~[/cyan]"
]

PROGRESS_FRAMES = [
    "[cyan]▱▱▱▱▱▱▱▱▱▱[/cyan]",
    "[cyan]▰▱▱▱▱▱▱▱▱▱[/cyan]",
    "[cyan]▰▰▱▱▱▱▱▱▱▱[/cyan]",
    "[cyan]▰▰▰▱▱▱▱▱▱▱[/cyan]",
    "[cyan]▰▰▰▰▱▱▱▱▱▱[/cyan]",
    "[cyan]▰▰▰▰▰▱▱▱▱▱[/cyan]",
    "[cyan]▰▰▰▰▰▰▱▱▱▱[/cyan]",
    "[cyan]▰▰▰▰▰▰▰▱▱▱[/cyan]",
    "[cyan]▰▰▰▰▰▰▰▰▱▱[/cyan]",
    "[cyan]▰▰▰▰▰▰▰▰▰▱[/cyan]",
    "[cyan]▰▰▰▰▰▰▰▰▰▰[/cyan]"
]

RADAR_FRAMES = [
    """
    [cyan]
        ╱─╲
       ╱   ╲
      │  ·  │
       ╲   ╱
        ╲─╱
    [/cyan]
    """,
    """
    [cyan]
        ╱─╲
       ╱ · ╲
      │     │
       ╲   ╱
        ╲─╱
    [/cyan]
    """,
    """
    [cyan]
        ╱─╲
       ╱   ╲
      │     │·
       ╲   ╱
        ╲─╱
    [/cyan]
    """,
    """
    [cyan]
        ╱─╲
       ╱   ╲
      │     │
       ╲ · ╱
        ╲─╱
    [/cyan]
    """
]

MATRIX_CHARS = ['0', '1', '█', '▓', '▒', '░']

# Animated greeting ASCII arts
GREETING_ARTS = [
    """
    [cyan]
         _______________
        |  ___________  |
        | |           | |
        | |  WELCOME  | |
        | |___________| |
        |_______________|
        \\_______________/
         \\             /
          \\___________/
    [/cyan]
    """,
    """
    [cyan]
        ╭─────────────╮
        │   HELLO!    │
        │  Ready to   │
        │   Scan?     │
        ╰─────────────╯
             \\│/
              ▼
    [/cyan]
    """,
    """
    [cyan]
       ┌─────────────┐
       │ ◉ ◉ ◉ ◉ ◉ │
       │             │
       │  SENTINEL   │
       │   ACTIVE    │
       └─────────────┘
    [/cyan]
    """
]

# Professional module icons using ASCII
MODULE_ICONS = {
    "xss_scanner": "[▸]",
    "sql_injection": "[◆]",
    "command_injection": "[⚡]",
    "ssrf_scanner": "[◈]",
    "rce_scanner": "[✱]",
    "http_scanner": "[▪]",
    "ssl_scanner": "[◉]",
    "info_disclosure": "[□]",
    "content_discovery": "[▫]"
}

# Vulnerability assessment modules
VULN_MODULES = {
    "xss_scanner": {
        "name": "XSS Scanner",
        "description": "Cross-Site Scripting vulnerability detection",
        "icon": MODULE_ICONS["xss_scanner"],
        "severity": "HIGH",
        "category": "INJECTION"
    },
    "sql_injection": {
        "name": "SQL Injection Scanner",
        "description": "SQL injection vulnerability detection",
        "icon": MODULE_ICONS["sql_injection"],
        "severity": "CRITICAL",
        "category": "INJECTION"
    },
    "command_injection": {
        "name": "Command Injection Scanner",
        "description": "OS command injection detection",
        "icon": MODULE_ICONS["command_injection"],
        "severity": "CRITICAL",
        "category": "INJECTION"
    },
    "ssrf_scanner": {
        "name": "SSRF Scanner",
        "description": "Server-Side Request Forgery detection",
        "icon": MODULE_ICONS["ssrf_scanner"],
        "severity": "HIGH",
        "category": "REQUEST"
    },
    "rce_scanner": {
        "name": "RCE Scanner",
        "description": "Remote Code Execution vulnerability detection",
        "icon": MODULE_ICONS["rce_scanner"],
        "severity": "CRITICAL",
        "category": "EXECUTION"
    },
    "http_scanner": {
        "name": "HTTP Security Scanner",
        "description": "HTTP security headers and configuration analysis",
        "icon": MODULE_ICONS["http_scanner"],
        "severity": "MEDIUM",
        "category": "CONFIGURATION"
    },
    "ssl_scanner": {
        "name": "SSL/TLS Scanner",
        "description": "SSL/TLS configuration and vulnerability analysis",
        "icon": MODULE_ICONS["ssl_scanner"],
        "severity": "MEDIUM",
        "category": "CRYPTOGRAPHY"
    },
    "info_disclosure": {
        "name": "Information Disclosure Scanner",
        "description": "Sensitive information exposure detection",
        "icon": MODULE_ICONS["info_disclosure"],
        "severity": "LOW",
        "category": "DISCLOSURE"
    },
    "content_discovery": {
        "name": "Content Discovery",
        "description": "Hidden files and directories discovery",
        "icon": MODULE_ICONS["content_discovery"],
        "severity": "INFO",
        "category": "DISCOVERY"
    }
}

class AnimationEngine:
    """ASCII Animation Engine for CLI effects"""
    
    def __init__(self, console):
        self.console = console
        self.stop_animation = False
        
    def animate_loading(self, message: str, duration: float = 2.0):
        """Display animated loading spinner"""
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = LOADING_FRAMES[frame_idx % len(LOADING_FRAMES)]
            self.console.print(f"\r{frame} {message}", end="")
            time.sleep(0.1)
            frame_idx += 1
        
        self.console.print(f"\r[green]✓[/green] {message}")
    
    def animate_progress_bar(self, message: str, steps: int = 10):
        """Display animated progress bar"""
        for i, frame in enumerate(PROGRESS_FRAMES):
            self.console.print(f"\r{message} {frame}", end="")
            time.sleep(0.15)
        self.console.print(f"\r{message} [green]▰▰▰▰▰▰▰▰▰▰[/green] [bold green]COMPLETE[/bold green]")
    
    def animate_scanning(self, duration: float = 3.0):
        """Display animated scanning effect"""
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = SCANNING_FRAMES[frame_idx % len(SCANNING_FRAMES)]
            self.console.print(frame, end="")
            time.sleep(0.2)
            # Clear previous frame
            self.console.print("\033[F" * 5, end="")
            frame_idx += 1
    
    def animate_pulse(self, message: str, duration: float = 2.0):
        """Display pulsing animation"""
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = PULSE_FRAMES[frame_idx % len(PULSE_FRAMES)]
            self.console.print(f"\r{frame} {message}", end="")
            time.sleep(0.2)
            frame_idx += 1
        
        self.console.print(f"\r[bold green]◉[/bold green] {message}")
    
    def animate_wave(self, message: str, duration: float = 1.5):
        """Display wave animation"""
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = WAVE_FRAMES[frame_idx % len(WAVE_FRAMES)]
            self.console.print(f"\r{message} {frame}", end="")
            time.sleep(0.15)
            frame_idx += 1
        
        self.console.print(f"\r{message} [green]~~~[/green]")
    
    def animate_radar(self, message: str, duration: float = 2.0):
        """Display radar scanning animation"""
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = RADAR_FRAMES[frame_idx % len(RADAR_FRAMES)]
            self.console.print(f"\n{message}")
            self.console.print(frame, end="")
            time.sleep(0.3)
            # Clear previous frame
            self.console.print("\033[F" * 7, end="")
            frame_idx += 1
    
    def animate_typing(self, text: str, delay: float = 0.03):
        """Display typing animation effect"""
        for char in text:
            self.console.print(char, end="")
            time.sleep(delay)
        self.console.print()
    
    def animate_matrix_rain(self, duration: float = 2.0):
        """Display matrix-style rain effect"""
        width = 80
        start_time = time.time()
        
        while time.time() - start_time < duration:
            line = ''.join(random.choice(MATRIX_CHARS) for _ in range(width))
            self.console.print(f"[dim cyan]{line}[/dim cyan]")
            time.sleep(0.05)
    
    def animate_countdown(self, seconds: int, message: str = "Starting in"):
        """Display countdown animation"""
        for i in range(seconds, 0, -1):
            self.console.print(f"\r{message} [bold cyan]{i}[/bold cyan]...", end="")
            time.sleep(1)
        self.console.print(f"\r{message} [bold green]GO![/bold green]   ")


class SentinelCLI:
    """Professional CLI class for Sentinel Security Scanner"""
    
    def __init__(self):
        self.console = console
        self.animator = AnimationEngine(console)
        self.current_target = None
        self.scan_history = []
        self.session_start = datetime.now()
        
    def display_banner(self):
        """Display the application banner with animation"""
        self.console.clear()
        
        # Animated initialization sequence
        init_steps = [
            "Loading core modules",
            "Initializing scanner engine",
            "Configuring security protocols",
            "Establishing secure connection",
            "System ready"
        ]
        
        for step in init_steps:
            self.animator.animate_loading(step, duration=0.5)
        
        self.console.print()
        
        # Display main banner with typing effect
        self.console.print(MAIN_BANNER)
        
        # Animated greeting
        greeting = random.choice(GREETING_ARTS)
        self.console.print(greeting)
        
        # Pulse animation for status
        self.animator.animate_pulse("System Status: OPERATIONAL", duration=1.0)
        self.console.print()
        
        # Display session info with animation
        session_panel = Panel(
            f"[bold white]Session Started:[/bold white] {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bold white]Engine Status:[/bold white] [green]OPERATIONAL[/green]\n"
            f"[bold white]Modules Loaded:[/bold white] {len(VULN_MODULES)}",
            title="[bold cyan][ SYSTEM STATUS ][/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE_EDGE
        )
        self.console.print(session_panel)
        self.console.print()
    
    def display_main_menu(self):
        """Display the main menu with professional styling"""
        # Header
        self.console.print(Rule("[bold cyan]VULNERABILITY ASSESSMENT MODULES[/bold cyan]", style="cyan"))
        self.console.print()
        
        # Create main modules table
        table = Table(
            box=box.HEAVY_EDGE,
            show_header=True,
            header_style="bold white on blue",
            border_style="bright_blue",
            title_style="bold cyan",
            padding=(0, 1)
        )
        
        table.add_column("ID", style="bold cyan", width=6, justify="center")
        table.add_column("Module", style="bold white", width=28)
        table.add_column("Category", style="cyan", width=15)
        table.add_column("Description", style="white")
        table.add_column("Risk", justify="center", width=12)
        
        # Add comprehensive scan option
        table.add_row(
            "[0]",
            "[bold yellow]COMPREHENSIVE SCAN[/bold yellow]",
            "ALL",
            "Execute all vulnerability assessment modules",
            "[bold red on black]FULL[/bold red on black]"
        )
        
        table.add_row("", "", "", "", "")  # Empty row for spacing
        
        # Add individual modules grouped by category
        for idx, (module_id, module_info) in enumerate(VULN_MODULES.items(), 1):
            severity_style = {
                "CRITICAL": "bold white on red",
                "HIGH": "bold red",
                "MEDIUM": "bold yellow",
                "LOW": "green",
                "INFO": "blue"
            }.get(module_info["severity"], "white")
            
            table.add_row(
                f"[{idx}]",
                f"{module_info['icon']} {module_info['name']}",
                module_info["category"],
                module_info["description"],
                f"[{severity_style}]{module_info['severity']}[/{severity_style}]"
            )
        
        self.console.print(table)
        self.console.print()
        
        # System commands section
        self.console.print(Rule("[bold cyan]SYSTEM COMMANDS[/bold cyan]", style="cyan"))
        
        cmd_table = Table(
            box=box.SIMPLE,
            show_header=False,
            border_style="cyan",
            padding=(0, 2)
        )
        
        cmd_table.add_column("Command", style="bold cyan", width=15)
        cmd_table.add_column("Description", style="white")
        
        cmd_table.add_row("[R]", "Review scan history and results")
        cmd_table.add_row("[C]", "Configure global scan parameters")
        cmd_table.add_row("[D]", "Documentation and usage guide")
        cmd_table.add_row("[S]", "System statistics and performance")
        cmd_table.add_row("[X]", "Exit Sentinel Framework")
        
        self.console.print(cmd_table)
        self.console.print()
        
        # Status bar
        status_text = f"[dim]Ready for input | Target: {self.current_target or 'Not Set'} | Session: {self._get_session_duration()}[/dim]"
        self.console.print(Panel(status_text, style="dim", box=box.MINIMAL))
    
    def _get_session_duration(self):
        """Calculate session duration"""
        duration = datetime.now() - self.session_start
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_target_url(self) -> Optional[str]:
        """Get and validate target URL from user"""
        self.console.print()
        self.console.print(Rule("[bold cyan]TARGET CONFIGURATION[/bold cyan]", style="cyan"))
        
        # Display target input interface
        target_box = Panel(
            "[bold white]Enter the target URL or domain for vulnerability assessment[/bold white]\n"
            "[dim]Format: https://example.com or example.com[/dim]",
            border_style="cyan",
            box=box.ROUNDED
        )
        self.console.print(target_box)
        
        target = Prompt.ask(
            "\n[bold cyan]TARGET[/bold cyan]",
            default=self.current_target if self.current_target else None
        )
        
        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Validate with animated loading
        self.console.print()
        self.animator.animate_wave("Validating target", duration=1.0)
        
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                self.console.print("[bold red][X] Invalid URL format[/bold red]")
                return None
            
            self.current_target = target
            
            # Animated validation steps
            validation_steps = [
                "Checking DNS resolution",
                "Verifying connectivity",
                "Analyzing target structure"
            ]
            
            for step in validation_steps:
                self.animator.animate_loading(step, duration=0.4)
            
            self.console.print()
            
            # Display validation success
            success_panel = Panel(
                f"[bold green][✓] Target Validated[/bold green]\n"
                f"[bold white]URL:[/bold white] {target}\n"
                f"[bold white]Domain:[/bold white] {parsed.netloc}\n"
                f"[bold white]Protocol:[/bold white] {parsed.scheme}",
                border_style="green",
                box=box.ROUNDED
            )
            self.console.print(success_panel)
            return target
            
        except Exception as e:
            self.console.print(f"[bold red][X] Validation Error: {e}[/bold red]")
            return None
    
    def get_scan_configuration(self) -> ScanConfig:
        """Get scan configuration with professional interface"""
        self.console.print()
        self.console.print(Rule("[bold cyan]SCAN CONFIGURATION[/bold cyan]", style="cyan"))
        
        # Scan intensity selection
        intensity_table = Table(
            title="[bold cyan]SELECT SCAN INTENSITY[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on blue"
        )
        
        intensity_table.add_column("Level", style="bold cyan", width=15)
        intensity_table.add_column("Mode", style="bold white", width=20)
        intensity_table.add_column("Description", style="white")
        intensity_table.add_column("Impact", style="yellow", width=15)
        
        scan_types = {
            "1": ("PASSIVE", ScanType.PASSIVE, "Non-intrusive reconnaissance only", "Minimal"),
            "2": ("ACTIVE", ScanType.ACTIVE, "Standard vulnerability testing", "Moderate"),
            "3": ("AGGRESSIVE", ScanType.AGGRESSIVE, "Comprehensive payload testing", "High")
        }
        
        for key, (name, _, desc, impact) in scan_types.items():
            color = {"PASSIVE": "green", "ACTIVE": "yellow", "AGGRESSIVE": "red"}.get(name, "white")
            intensity_table.add_row(
                f"[{key}]",
                f"[{color}]{name}[/{color}]",
                desc,
                impact
            )
        
        self.console.print(intensity_table)
        
        scan_choice = Prompt.ask(
            "\n[bold cyan]Select intensity level[/bold cyan]",
            choices=["1", "2", "3"],
            default="2"
        )
        
        scan_type = scan_types[scan_choice][1]
        scan_name = scan_types[scan_choice][0]
        
        # Advanced configuration
        self.console.print()
        advanced = Confirm.ask("[bold cyan]Configure advanced parameters?[/bold cyan]", default=False)
        
        timeout = 3600
        rate_limit = 1
        max_depth = 3
        debug_mode = False
        
        if advanced:
            self.console.print()
            self.console.print(Panel("[bold white]ADVANCED CONFIGURATION[/bold white]", border_style="cyan"))
            
            timeout = int(Prompt.ask("[cyan]Timeout (seconds)[/cyan]", default="3600"))
            rate_limit = int(Prompt.ask("[cyan]Rate limit (req/sec)[/cyan]", default="1"))
            max_depth = int(Prompt.ask("[cyan]Max crawl depth[/cyan]", default="3"))
            debug_mode = Confirm.ask("[cyan]Enable debug mode?[/cyan]", default=False)
        else:
            debug_mode = Confirm.ask("\n[bold cyan]Enable debug mode?[/bold cyan]", default=False)
        
        config = ScanConfig(
            target=self.current_target,
            scan_type=scan_type,
            timeout=timeout,
            rate_limit=rate_limit,
            max_depth=max_depth,
            debug=debug_mode
        )
        
        # Display configuration summary with ASCII box
        self.console.print()
        config_text = f"""
┌─────────────────────────────────────────┐
│         SCAN CONFIGURATION SUMMARY       │
├─────────────────────────────────────────┤
│  Intensity  : {scan_name:<26} │
│  Timeout    : {timeout:<26} │
│  Rate Limit : {rate_limit} req/s{' '*(23-len(str(rate_limit)))} │
│  Max Depth  : {max_depth:<26} │
│  Debug Mode : {'ENABLED' if debug_mode else 'DISABLED':<26} │
└─────────────────────────────────────────┘
"""
        self.console.print(Panel(config_text, border_style="cyan", box=box.MINIMAL))
        
        return config
    
    async def run_single_module(self, module_name: str):
        """Run a single vulnerability scanner module"""
        if module_name not in VULN_MODULES:
            self.console.print("[bold red][X] Invalid module selected[/bold red]")
            return
        
        module_info = VULN_MODULES[module_name]
        
        # Display module header with ASCII art
        self.console.print("\n")
        module_header = f"""
╔══════════════════════════════════════════╗
║  {module_info['icon']} {module_info['name']:^36} │
║  Category: {module_info['category']:<29} │
║  Risk Level: {module_info['severity']:<27} │
╚══════════════════════════════════════════╝
"""
        self.console.print(Panel(module_header, border_style="cyan", box=box.MINIMAL))
        
        # Get target
        target = self.get_target_url()
        if not target:
            return
        
        # Get configuration
        config = self.get_scan_configuration()
        
        # Confirm scan
        self.console.print()
        if not Confirm.ask(f"[bold cyan]Initialize {module_info['name']}?[/bold cyan]"):
            self.console.print("[yellow]Operation cancelled[/yellow]")
            return
        
        # Animated countdown before scan
        self.console.print()
        self.animator.animate_countdown(3, "Initializing scan in")
        self.console.print()
        
        # Run scan with professional progress display
        with Progress(
            TextColumn("[bold cyan]{task.description}"),
            SpinnerColumn("dots", style="cyan"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        ) as progress:
            
            scan_task = progress.add_task(
                f"Executing {module_info['name']}",
                total=100
            )
            
            try:
                # Create scan job
                scan_job = await scanner_engine.create_scan(
                    target=target,
                    modules=[module_name],
                    config=config
                )
                
                progress.update(scan_task, advance=30, description="Initializing scanner...")
                await asyncio.sleep(0.5)
                
                # Execute scan
                progress.update(scan_task, advance=20, description="Performing vulnerability assessment...")
                completed_job = await scanner_engine.execute_scan(scan_job.id)
                
                progress.update(scan_task, advance=30, description="Analyzing results...")
                await asyncio.sleep(0.5)
                
                # Get results
                results = scanner_engine.get_scan_results(completed_job.id)
                progress.update(scan_task, advance=20, description="Generating report...")
                
                # Animated completion
                self.console.print()
                self.animator.animate_pulse("Scan completed successfully", duration=1.0)
                
                # Display results
                await self.display_scan_results(results, module_info)
                
                # Save results
                self.save_scan_results(results, module_name, target)
                
                # Generate POC if vulnerabilities found
                if results and results.get("vulnerabilities"):
                    await self.generate_poc_report(target, module_name, results)
                
            except Exception as e:
                self.console.print(f"\n[bold red][X] Scan failed: {e}[/bold red]")
                if config.debug:
                    import traceback
                    self.console.print(traceback.format_exc())
    
    async def run_comprehensive_scan(self):
        """Run all vulnerability assessment modules"""
        self.console.print("\n")
        
        # Display comprehensive scan header
        comp_header = """
╔════════════════════════════════════════════════════╗
║         COMPREHENSIVE VULNERABILITY SCAN           ║
║                                                    ║
║  This operation will execute all available        ║
║  vulnerability assessment modules sequentially.    ║
║                                                    ║
║  Estimated Duration: 10-30 minutes                ║
╚════════════════════════════════════════════════════╝
"""
        self.console.print(Panel(comp_header, border_style="yellow", box=box.MINIMAL))
        
        # Get target
        target = self.get_target_url()
        if not target:
            return
        
        # Get configuration
        config = self.get_scan_configuration()
        
        # Confirm scan
        self.console.print()
        if not Confirm.ask("[bold yellow]Proceed with comprehensive scan?[/bold yellow]"):
            self.console.print("[yellow]Operation cancelled[/yellow]")
            return
        
        # Get available modules
        available_modules = list(VULN_MODULES.keys())
        
        # Run scan with progress
        self.console.print()
        with Progress(
            TextColumn("[bold cyan]{task.description}"),
            SpinnerColumn("dots", style="cyan"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=self.console
        ) as progress:
            
            main_task = progress.add_task(
                "Comprehensive scan in progress",
                total=len(available_modules)
            )
            
            all_results = {}
            total_vulns = 0
            
            for module_name in available_modules:
                module_info = VULN_MODULES[module_name]
                progress.update(
                    main_task,
                    description=f"Scanning: {module_info['name']}"
                )
                
                try:
                    # Create and execute scan
                    scan_job = await scanner_engine.create_scan(
                        target=target,
                        modules=[module_name],
                        config=config
                    )
                    
                    completed_job = await scanner_engine.execute_scan(scan_job.id)
                    results = scanner_engine.get_scan_results(completed_job.id)
                    
                    if results:
                        all_results[module_name] = results
                        total_vulns += len(results.get("vulnerabilities", []))
                    
                except Exception as e:
                    self.console.print(f"\n[yellow][!] {module_info['name']} failed: {e}[/yellow]")
                
                progress.update(main_task, advance=1)
            
            # Display comprehensive results
            await self.display_comprehensive_results(all_results, total_vulns)
            
            # Save comprehensive report
            self.save_comprehensive_report(all_results, target)
    
    async def display_scan_results(self, results: Dict[str, Any], module_info: Dict[str, str]):
        """Display scan results in a professional format"""
        if not results:
            self.console.print("[yellow]No results available[/yellow]")
            return
        
        # Results header
        self.console.print("\n")
        self.console.print(Rule("[bold green]SCAN RESULTS[/bold green]", style="green"))
        
        # Summary statistics
        vulns = results.get("vulnerabilities", [])
        vuln_count = len(vulns)
        severity_counts = results.get("vulnerabilities_by_severity", {})
        
        # Create summary box
        target_display = str(results.get('target', 'N/A'))[:35]
        module_display = module_info['name'][:35]
        status_display = str(results.get('status', 'N/A'))[:35]
        duration_display = str(results.get('duration', 'N/A'))[:35]
        
        summary_ascii = f"""
┌─────────────────────────────────────────────────┐
│              VULNERABILITY SUMMARY               │
├─────────────────────────────────────────────────┤
│  Target    : {target_display:<35} │
│  Module    : {module_display:<35} │
│  Status    : {status_display:<35} │
│  Duration  : {duration_display:<35} │
├─────────────────────────────────────────────────┤
│              FINDINGS BREAKDOWN                  │
├─────────────────────────────────────────────────┤
│  Total Found : {vuln_count:<33} │
│  ├─ Critical : {severity_counts.get('critical', 0):<33} │
│  ├─ High     : {severity_counts.get('high', 0):<33} │
│  ├─ Medium   : {severity_counts.get('medium', 0):<33} │
│  ├─ Low      : {severity_counts.get('low', 0):<33} │
│  └─ Info     : {severity_counts.get('info', 0):<33} │
└─────────────────────────────────────────────────┘
"""
        
        self.console.print(Panel(summary_ascii, border_style="green", box=box.MINIMAL))
        
        # Display vulnerabilities if found
        if vulns:
            self.console.print("\n")
            vuln_table = Table(
                title="[bold red]DETECTED VULNERABILITIES[/bold red]",
                box=box.DOUBLE_EDGE,
                show_header=True,
                header_style="bold white on red"
            )
            
            vuln_table.add_column("#", justify="center", width=5)
            vuln_table.add_column("Severity", justify="center", width=12)
            vuln_table.add_column("Vulnerability", style="bold white")
            vuln_table.add_column("Description", style="white")
            vuln_table.add_column("Confidence", justify="center", width=12)
            
            for idx, vuln in enumerate(vulns[:15], 1):  # Show first 15
                severity = vuln.get("severity", "unknown")
                severity_style = {
                    "critical": "bold white on red",
                    "high": "bold red",
                    "medium": "bold yellow",
                    "low": "green",
                    "info": "blue"
                }.get(severity.lower(), "white")
                
                desc = vuln.get("description", "N/A")
                if len(desc) > 50:
                    desc = desc[:47] + "..."
                
                vuln_table.add_row(
                    str(idx),
                    f"[{severity_style}]{severity.upper()}[/{severity_style}]",
                    vuln.get("name", "N/A"),
                    desc,
                    f"{vuln.get('confidence', 0)}%"
                )
            
            self.console.print(vuln_table)
            
            if len(vulns) > 15:
                self.console.print(f"\n[dim]... and {len(vulns) - 15} additional vulnerabilities[/dim]")
        else:
            success_msg = """
            ┌─────────────────────────────┐
            │    [✓] SCAN COMPLETED       │
            │    No vulnerabilities found  │
            └─────────────────────────────┘
            """
            self.console.print(Panel(success_msg, border_style="green", box=box.MINIMAL))
    
    async def display_comprehensive_results(self, all_results: Dict[str, Any], total_vulns: int):
        """Display comprehensive scan results"""
        self.console.print("\n")
        self.console.print(Rule("[bold green]COMPREHENSIVE SCAN COMPLETE[/bold green]", style="green"))
        
        # Overall summary
        summary_text = f"""
╔═══════════════════════════════════════════════╗
║           COMPREHENSIVE SCAN SUMMARY          ║
╠═══════════════════════════════════════════════╣
║  Modules Executed     : {len(all_results):<21} ║
║  Total Vulnerabilities: {total_vulns:<21} ║
║  Scan Status         : COMPLETED              ║
╚═══════════════════════════════════════════════╝
"""
        self.console.print(Panel(summary_text, border_style="green", box=box.MINIMAL))
        
        # Module-wise results
        if all_results:
            self.console.print("\n")
            module_table = Table(
                title="[bold cyan]MODULE EXECUTION SUMMARY[/bold cyan]",
                box=box.HEAVY_EDGE,
                show_header=True,
                header_style="bold white on blue"
            )
            
            module_table.add_column("Module", style="bold white")
            module_table.add_column("Status", justify="center", width=10)
            module_table.add_column("Findings", justify="center", width=10)
            module_table.add_column("Critical", justify="center", style="red", width=10)
            module_table.add_column("High", justify="center", style="red", width=10)
            module_table.add_column("Medium", justify="center", style="yellow", width=10)
            module_table.add_column("Low", justify="center", style="green", width=10)
            
            for module_name, results in all_results.items():
                module_info = VULN_MODULES.get(module_name, {})
                vulns = results.get("vulnerabilities", [])
                severity_counts = results.get("vulnerabilities_by_severity", {})
                
                status = "[✓]" if results.get("status") == "completed" else "[X]"
                status_color = "green" if status == "[✓]" else "red"
                
                module_table.add_row(
                    f"{module_info.get('icon', '')} {module_info.get('name', module_name)}",
                    f"[{status_color}]{status}[/{status_color}]",
                    str(len(vulns)),
                    str(severity_counts.get("critical", 0)),
                    str(severity_counts.get("high", 0)),
                    str(severity_counts.get("medium", 0)),
                    str(severity_counts.get("low", 0))
                )
            
            self.console.print(module_table)
    
    async def generate_poc_report(self, target: str, module_name: str, results: Dict[str, Any]):
        """Generate POC report for vulnerabilities"""
        if not results.get("vulnerabilities"):
            return
        
        self.console.print("\n")
        if Confirm.ask("[bold cyan]Generate Proof-of-Concept report?[/bold cyan]"):
            with self.console.status("[cyan]Generating POC report...", spinner="dots"):
                try:
                    poc_report = await poc_generator.generate_poc_for_module(
                        target=target,
                        module_name=module_name,
                        scan_result=results,
                        auto_display=False
                    )
                    
                    if poc_report.get("generated"):
                        self.console.print("[bold green][✓] POC report generated successfully[/bold green]")
                        if poc_report.get("file_path"):
                            self.console.print(f"[dim]Location: {poc_report['file_path']}[/dim]")
                    else:
                        self.console.print(f"[yellow][!] {poc_report.get('message', 'POC generation failed')}[/yellow]")
                        
                except Exception as e:
                    self.console.print(f"[red][X] POC generation error: {e}[/red]")
    
    def save_scan_results(self, results: Dict[str, Any], module_name: str, target: str):
        """Save scan results to file"""
        try:
            results_dir = Path("scan_results")
            results_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{module_name}_{timestamp}.json"
            file_path = results_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, default=str)
            
            self.console.print(f"\n[green][✓] Results saved: {file_path}[/green]")
            
        except Exception as e:
            self.console.print(f"[red][X] Error saving results: {e}[/red]")
    
    def save_comprehensive_report(self, all_results: Dict[str, Any], target: str):
        """Save comprehensive scan report"""
        try:
            results_dir = Path("scan_results")
            results_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"comprehensive_scan_{timestamp}.json"
            file_path = results_dir / filename
            
            report = {
                "scan_type": "comprehensive",
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "modules_executed": len(all_results),
                "results": all_results
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, default=str)
            
            self.console.print(f"\n[green][✓] Comprehensive report saved: {file_path}[/green]")
            
        except Exception as e:
            self.console.print(f"[red][X] Error saving report: {e}[/red]")
    
    def show_documentation(self):
        """Display documentation"""
        doc_text = """
# SENTINEL SECURITY SCANNER - DOCUMENTATION

## OVERVIEW
Sentinel is a professional vulnerability assessment framework designed
for comprehensive security testing of web applications and services.

## SCAN MODES

### PASSIVE SCAN
- Non-intrusive reconnaissance
- No active exploitation attempts
- Safe for production environments

### ACTIVE SCAN
- Standard vulnerability testing
- Moderate payload injection
- Recommended for staging environments

### AGGRESSIVE SCAN
- Comprehensive payload testing
- Full exploitation attempts
- Development environments only

## VULNERABILITY MODULES

### INJECTION ATTACKS
- XSS Scanner: Cross-Site Scripting detection
- SQL Injection: Database injection vulnerabilities
- Command Injection: OS command execution flaws

### REQUEST FORGERY
- SSRF Scanner: Server-Side Request Forgery

### CODE EXECUTION
- RCE Scanner: Remote Code Execution vulnerabilities

### CONFIGURATION
- HTTP Security: Security headers analysis
- SSL/TLS Scanner: Cryptographic configuration

### INFORMATION DISCLOSURE
- Info Disclosure: Sensitive data exposure
- Content Discovery: Hidden resources

## BEST PRACTICES
1. Always obtain proper authorization before scanning
2. Start with passive scans for initial assessment
3. Use rate limiting to avoid service disruption
4. Review all findings before reporting
5. Generate POC reports for validation

## SUPPORT
For additional assistance, consult the project documentation
or contact the security team.
"""
        self.console.print(Markdown(doc_text))
    
    def show_statistics(self):
        """Display system statistics"""
        stats_ascii = f"""
╔════════════════════════════════════════════════╗
║             SYSTEM STATISTICS                  ║
╠════════════════════════════════════════════════╣
║  Session Duration  : {self._get_session_duration():<26} ║
║  Modules Available : {len(VULN_MODULES):<26} ║
║  Scans Completed   : {len(self.scan_history):<26} ║
║  Current Target    : {(self.current_target or 'Not Set')[:26]:<26} ║
║  Engine Version    : 2.0.0                     ║
║  Framework Status  : OPERATIONAL                ║
╚════════════════════════════════════════════════╝
"""
        self.console.print(Panel(stats_ascii, border_style="cyan", box=box.MINIMAL))
    
    async def run(self):
        """Main CLI loop"""
        self.display_banner()
        
        while True:
            try:
                self.console.print("\n")
                self.display_main_menu()
                
                choice = Prompt.ask(
                    "[bold cyan]COMMAND[/bold cyan]",
                    default="D"
                ).upper()
                
                if choice == "X":
                    # Exit confirmation with ASCII art
                    exit_msg = """
                    ┌─────────────────────────┐
                    │    EXIT CONFIRMATION    │
                    │                         │
                    │  Terminate Sentinel?    │
                    └─────────────────────────┘
                    """
                    self.console.print(Panel(exit_msg, border_style="yellow", box=box.MINIMAL))
                    
                    if Confirm.ask("[bold yellow]Confirm exit?[/bold yellow]"):
                        goodbye_art = """
                        [cyan]
                        ╔═══════════════════════╗
                        ║   SESSION TERMINATED  ║
                        ║                       ║
                        ║   Stay Secure!        ║
                        ╚═══════════════════════╝
                        [/cyan]
                        """
                        self.console.print(goodbye_art)
                        break
                
                elif choice == "D":
                    self.show_documentation()
                
                elif choice == "R":
                    self.console.print("[yellow]Feature in development: Scan history review[/yellow]")
                
                elif choice == "C":
                    self.console.print("[yellow]Feature in development: Global configuration[/yellow]")
                
                elif choice == "S":
                    self.show_statistics()
                
                elif choice == "0":
                    await self.run_comprehensive_scan()
                
                elif choice.isdigit():
                    idx = int(choice)
                    if 1 <= idx <= len(VULN_MODULES):
                        module_name = list(VULN_MODULES.keys())[idx - 1]
                        await self.run_single_module(module_name)
                    else:
                        self.console.print("[red][X] Invalid selection[/red]")
                
                else:
                    self.console.print("[red][X] Unknown command[/red]")
                
                # Pause before showing menu again (except for doc/stats)
                if choice not in ["D", "S", "X"]:
                    self.console.print("\n")
                    Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
                    self.console.clear()
                    self.console.print(MAIN_BANNER)
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupt detected[/yellow]")
                if Confirm.ask("[bold yellow]Exit Sentinel?[/bold yellow]"):
                    self.console.print("[cyan]Session terminated[/cyan]")
                    break
            except Exception as e:
                self.console.print(f"[red][X] Unexpected error: {e}[/red]")
                if settings.debug:
                    import traceback
                    self.console.print(traceback.format_exc())


def main():
    """Main entry point for the CLI"""
    try:
        # Create and run the CLI
        cli = SentinelCLI()
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Session interrupted[/yellow]")
        console.print("[cyan]Sentinel terminated[/cyan]")
    except Exception as e:
        console.print(f"[bold red]Fatal error: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
