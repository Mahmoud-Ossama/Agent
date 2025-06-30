#!/usr/bin/env python3
"""
Enhanced AI-Powered Penetration Testing Agent
Dynamic command execution based on LLM decisions with MCP support
"""

import os
import sys
import argparse
import logging
import asyncio
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.main_agent import EnhancedPenTestAgent
from agent.dynamic_agent import DynamicPenTestAgent
from agent.mcp_agent import MCPPenTestAgent
from mcp_client import run_human_mcp_pentest
from mcp_client import run_human_mcp_pentest

def setup_logging(log_level="INFO"):
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=[
            logging.FileHandler(f'pentest_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def validate_target(target_url):
    """Validate target URL format"""
    if not target_url:
        raise ValueError("Target URL cannot be empty")
    
    if not target_url.startswith(('http://', 'https://')):
        # Add http:// if no protocol specified
        target_url = 'http://' + target_url
    
    return target_url

async def run_async_mode(args):
    """Run MCP modes that require async execution"""
    target_url = validate_target(args.target)
    
    if args.mode == "mcp_human":
        await run_human_mcp_pentest(target_url)
        return
    else:
        raise ValueError(f"Unknown async mode: {args.mode}")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced AI-Powered Penetration Testing Agent with MCP Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Agent Modes:
  intelligent  - AI-driven strategic decisions (recommended)
  dynamic      - Direct command execution focus
  mcp_basic    - MCP-controlled basic mode  
  mcp_human    - MCP with human-like typing simulation

Examples:
  python run_enhanced_agent.py --target http://example.com
  python run_enhanced_agent.py --target example.com --mode dynamic --log-level DEBUG
  python run_enhanced_agent.py --target 192.168.1.100 --mode mcp_human
  python run_enhanced_agent.py --target vulnerable-app.local --mode intelligent
        """
    )
    
    parser.add_argument(
        "--target", 
        required=True, 
        help="Target URL or IP address for penetration testing"
    )
    
    parser.add_argument(
        "--mode",
        choices=["intelligent", "dynamic", "mcp_basic", "mcp_human", "mcp_parallel"],
        default="intelligent",
        help="Agent mode selection"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level"
    )
    
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Output directory for results"
    )
    
    parser.add_argument(
        "--max-terminals",
        type=int,
        default=4,
        help="Maximum number of parallel terminals (default: 4)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    try:
        # Validate and normalize target
        target_url = validate_target(args.target)
        logger.info(f"Target validated: {target_url}")
        
        # Create output directory
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Handle async modes
        if args.mode in ["mcp_human"]:
            logger.info(f"Running async mode: {args.mode}")
            asyncio.run(run_async_mode(args))
            return
        
        # Initialize agent based on mode
        if args.mode == "intelligent":
            logger.info("🧠 Initializing Intelligent AI-Powered Agent")
            agent = EnhancedPenTestAgent(target_url)
            
        elif args.mode == "dynamic":
            logger.info("⚡ Initializing Dynamic Command Agent")
            agent = DynamicPenTestAgent(target_url)
            
        elif args.mode == "mcp_basic":
            logger.info("🔌 Initializing MCP-Enhanced Agent")
            agent = MCPPenTestAgent(target_url, enable_parallel=False)
            
        elif args.mode == "mcp_parallel":
            logger.info("🖥️  Initializing Multi-Terminal Parallel MCP Agent")
            agent = MCPPenTestAgent(target_url, enable_parallel=True, max_terminals=args.max_terminals)
            
        else:
            raise ValueError(f"Unknown mode: {args.mode}")
        
        # Update configuration
        if hasattr(agent, 'results_dir') and args.output_dir != "results":
            agent.results_dir = args.output_dir
            os.makedirs(agent.results_dir, exist_ok=True)
        
        if hasattr(agent, 'max_terminals'):
            agent.max_terminals = args.max_terminals
        
        logger.info(f"🚀 Starting penetration test in {args.mode} mode")
        logger.info(f"🎯 Target: {target_url}")
        logger.info(f"📁 Output Directory: {getattr(agent, 'results_dir', args.output_dir)}")
        
        # Run the agent
        if hasattr(agent, 'run_full_assessment'):
            agent.run_full_assessment()
        else:
            agent.run()
        
        logger.info("✅ Penetration test completed successfully")
        print(f"\n🎉 Results saved to: {getattr(agent, 'results_dir', args.output_dir)}")
        
    except KeyboardInterrupt:
        logger.warning("⚠️  Penetration test interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Error running penetration test: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
