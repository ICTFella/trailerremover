#!/usr/bin/env python3
"""
Windows Service Wrapper for PRP Trailer Remover

This script creates a Windows service that runs trailerremover.py
with administrator privileges.
"""

import sys
import os
import time
import logging
import subprocess
import threading
from pathlib import Path

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    print("pywin32 not installed. Install with: pip install pywin32")
    sys.exit(1)

# Configure logging for the service
LOG_FILE = Path(__file__).parent / "trailerremover_service.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('TrailerRemoverService')

class TrailerRemoverService(win32serviceutil.ServiceFramework):
    """Windows Service for PRP Trailer Remover"""
    
    _svc_name_ = "TrailerRemoverService"
    _svc_display_name_ = "PRP Trailer Remover Service"
    _svc_description_ = "Service that removes PRP trailers from TCP packets on port 102"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.process = None
        
        # Path to the main script
        self.script_path = Path(__file__).parent / "trailerremover.py"
        
        logger.info(f"Service initialized. Script path: {self.script_path}")
    
    def SvcStop(self):
        """Called when the service is asked to stop"""
        logger.info("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_running = False
        
        # Terminate the subprocess if it's running
        if self.process and self.process.poll() is None:
            try:
                logger.info("Terminating trailerremover.py process")
                self.process.terminate()
                # Wait up to 10 seconds for graceful shutdown
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning("Process didn't terminate gracefully, killing it")
                    self.process.kill()
            except Exception as e:
                logger.error(f"Error stopping process: {e}")
        
        win32event.SetEvent(self.hWaitStop)
        logger.info("Service stopped")
    
    def SvcDoRun(self):
        """Called when the service is started"""
        logger.info("Service starting")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        try:
            self.main()
        except Exception as e:
            logger.error(f"Service error: {e}")
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_ERROR_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, str(e))
            )
    
    def main(self):
        """Main service logic"""
        logger.info("Starting main service loop")
        
        while self.is_running:
            try:
                # Check if script exists
                if not self.script_path.exists():
                    logger.error(f"Script not found: {self.script_path}")
                    time.sleep(30)
                    continue
                
                # Start the trailerremover.py script
                logger.info(f"Starting trailerremover.py: {self.script_path}")
                
                self.process = subprocess.Popen(
                    [sys.executable, str(self.script_path)],
                    cwd=str(self.script_path.parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )
                
                # Monitor the process
                while self.is_running and self.process.poll() is None:
                    # Check if service should stop
                    result = win32event.WaitForSingleObject(self.hWaitStop, 1000)
                    if result == win32event.WAIT_OBJECT_0:
                        break
                
                # Process finished or service stopping
                if self.process.poll() is not None:
                    stdout, stderr = self.process.communicate()
                    return_code = self.process.returncode
                    
                    if return_code != 0:
                        logger.error(f"trailerremover.py exited with code {return_code}")
                        if stdout:
                            logger.error(f"STDOUT: {stdout}")
                        if stderr:
                            logger.error(f"STDERR: {stderr}")
                        
                        # Wait before restarting
                        if self.is_running:
                            logger.info("Restarting in 10 seconds...")
                            time.sleep(10)
                    else:
                        logger.info("trailerremover.py exited normally")
                
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                if self.is_running:
                    time.sleep(10)  # Wait before retry
        
        logger.info("Service main loop ended")

def install_service():
    """Install the service"""
    try:
        win32serviceutil.InstallService(
            TrailerRemoverService._svc_reg_class_,
            TrailerRemoverService._svc_name_,
            TrailerRemoverService._svc_display_name_,
            description=TrailerRemoverService._svc_description_,
            startType=win32service.SERVICE_AUTO_START,
            account=None,  # LocalSystem account (runs as admin)
            password=None
        )
        print(f"Service '{TrailerRemoverService._svc_display_name_}' installed successfully!")
        print("Use 'net start TrailerRemoverService' to start the service")
        return True
    except Exception as e:
        print(f"Failed to install service: {e}")
        return False

def remove_service():
    """Remove the service"""
    try:
        win32serviceutil.RemoveService(TrailerRemoverService._svc_name_)
        print(f"Service '{TrailerRemoverService._svc_display_name_}' removed successfully!")
        return True
    except Exception as e:
        print(f"Failed to remove service: {e}")
        return False

def main():
    """Main function to handle command line arguments"""
    if len(sys.argv) == 1:
        # No arguments - try to start as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(TrailerRemoverService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments
        command = sys.argv[1].lower()
        
        if command == 'install':
            install_service()
        elif command == 'remove':
            remove_service()
        elif command == 'start':
            win32serviceutil.StartService(TrailerRemoverService._svc_name_)
            print("Service started")
        elif command == 'stop':
            win32serviceutil.StopService(TrailerRemoverService._svc_name_)
            print("Service stopped")
        elif command == 'restart':
            win32serviceutil.RestartService(TrailerRemoverService._svc_name_)
            print("Service restarted")
        elif command == 'debug':
            # Run in debug mode (not as service)
            service = TrailerRemoverService(sys.argv)
            service.main()
        else:
            print("Usage:")
            print("  python trailerremover_service.py install   - Install service")
            print("  python trailerremover_service.py remove    - Remove service")
            print("  python trailerremover_service.py start     - Start service")
            print("  python trailerremover_service.py stop      - Stop service")
            print("  python trailerremover_service.py restart   - Restart service")
            print("  python trailerremover_service.py debug     - Run in debug mode")

if __name__ == '__main__':
    main() 