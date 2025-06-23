#!/usr/bin/env python3
"""
Dynamic AI-Powered Penetration Testing Agent
LLM-driven command execution for penetration testing
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.dynamic_agent import DynamicPenTestAgent

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

def main():
    parser = argparse.ArgumentParser(
        description="Dynamic AI-Powered Penetration Testing Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_dynamic_agent.py --target http://example.com
  python run_dynamic_agent.py --target 192.168.1.100 --log-level DEBUG
  python run_dynamic_agent.py --target vulnerable-app.local --max-iterations 10
        """
    )
    
    parser.add_argument(
        "--target", 
        required=True, 
        help="Target URL or IP address for penetration testing"
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
        "--max-iterations",
        type=int,
        default=5,
        help="Maximum iterations per stage"
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
        
        # Initialize Dynamic Agent
        logger.info("⚡ Initializing Dynamic Command Agent")
        agent = DynamicPenTestAgent(target_url)
        
        # Update configuration
        if hasattr(agent, 'results_dir') and args.output_dir != "results":
            agent.results_dir = args.output_dir
            os.makedirs(agent.results_dir, exist_ok=True)
        
        logger.info(f"🚀 Starting dynamic penetration test")
        logger.info(f"🎯 Target: {target_url}")
        logger.info(f"📁 Output Directory: {getattr(agent, 'results_dir', args.output_dir)}")
          # Run the penetration test
        agent.run()
        
        logger.info("✅ Penetration test completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("⏹️  Penetration test interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Error running penetration test: {str(e)}")
        if args.log_level == "DEBUG":
            import traceback
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
