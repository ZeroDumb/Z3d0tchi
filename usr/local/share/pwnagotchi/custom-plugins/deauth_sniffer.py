import logging
import threading
import time
import os
from datetime import datetime, timedelta
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.faces as faces

class DeauthSniffer(plugins.Plugin):
    __author__ = 'ZeroDumb'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Sniffs for deauthentication frames and logs them.'
    __name__ = 'DeauthSniffer'
    __help__ = """
    Sniffs for deauthentication frames and logs them.
    """
    __defaults__ = {
        'enabled': False,
        'whitelist': ['00:11:22:33:44:55', 'aa:bb:cc:dd:ee:ff'],
        'debug': False,
        'log_file': '/home/pi/deauth_detections.log',
        'cleanup_interval': 3600,  # Cleanup old detections every hour
        'detection_timeout': 300,   # Remove detections after 5 minutes
        'ui_update_interval': 5,    # Update UI every 5 seconds
        'max_detections': 1000,     # Maximum number of detections to keep in memory
        'message_duration': 10      # How long to show the message in seconds
    }

    def __init__(self):
        self.ready = False
        self.detected_bssids = {}  # Changed to dict to store timestamps
        self.whitelist = []
        self.debug = False
        self.log_file = None
        self.last_ui_update = 0
        self.last_cleanup = 0
        self.lock = threading.Lock()
        self.message_expiry = 0
        self.current_message = None

    def _log_detection(self, mac, frame_data=None):
        """
        Log deauth detection to file
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"[{timestamp}] Deauth detected from MAC: {mac}"
            if frame_data:
                log_entry += f" | Frame data: {frame_data}"
            log_entry += "\n"
            
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
                
            if self.debug:
                logging.debug(f"[DeauthSniffer] Logged detection to {self.log_file}")
        except Exception as e:
            logging.error(f"[DeauthSniffer] Error writing to log file: {str(e)}")

    def _cleanup_old_detections(self):
        """
        Remove old detections to prevent memory issues
        """
        try:
            current_time = time.time()
            if current_time - self.last_cleanup < self.options['cleanup_interval']:
                return

            with self.lock:
                # Remove old detections
                timeout = self.options['detection_timeout']
                self.detected_bssids = {mac: ts for mac, ts in self.detected_bssids.items() 
                                      if current_time - ts < timeout}

                # If still too many, remove oldest
                if len(self.detected_bssids) > self.options['max_detections']:
                    sorted_detections = sorted(self.detected_bssids.items(), key=lambda x: x[1])
                    self.detected_bssids = dict(sorted_detections[-self.options['max_detections']:])

            self.last_cleanup = current_time
            if self.debug:
                logging.debug(f"[DeauthSniffer] Cleaned up old detections. Current count: {len(self.detected_bssids)}")
        except Exception as e:
            logging.error(f"[DeauthSniffer] Error during cleanup: {str(e)}")

    def on_loaded(self):
        """
        Called when the plugin gets loaded
        """
        try:
            # Load whitelist from config
            if 'whitelist' in self.options:
                self.whitelist = [mac.lower() for mac in self.options['whitelist']]
            
            # Load debug setting
            self.debug = self.options.get('debug', False)
            
            # Load log file path
            self.log_file = self.options.get('log_file', '/home/pi/deauth_detections.log')
            
            # Create log file if it doesn't exist
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'w') as f:
                    f.write(f"Deauth Detection Log - Started {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n")
            
            logging.info(f"[DeauthSniffer] Plugin loaded. Whitelist: {self.whitelist}")
            logging.info(f"[DeauthSniffer] Logging deauth detections to: {self.log_file}")
            if self.debug:
                logging.info(f"[DeauthSniffer] Debug mode: Enabled")
            self.ready = True
        except Exception as e:
            logging.error(f"[DeauthSniffer] Error loading plugin: {str(e)}")
            self.ready = False

    def on_unload(self):
        """
        Called when the plugin gets unloaded
        """
        try:
            logging.info("[DeauthSniffer] Plugin unloaded")
        except Exception as e:
            logging.error(f"[DeauthSniffer] Error unloading plugin: {str(e)}")

    def on_ui_update(self, ui):
        """
        Called when the UI is updated
        """
        try:
            current_time = time.time()
            
            # Clear message if it has expired
            if self.current_message and current_time > self.message_expiry:
                self.current_message = None
                ui.remove('deauth_status')
                return

            # Update or set the deauth status message
            if self.current_message:
                ui.set('deauth_status', self.current_message)
        except Exception as e:
            logging.error(f"[DeauthSniffer] Error updating UI: {str(e)}")

    def on_wifi_update(self, agent, access_points):
        """
        Called when the wifi information is updated
        """
        if not self.ready:
            return

        try:
            current_time = time.time()
            
            # Rate limit UI updates
            if current_time - self.last_ui_update < self.options['ui_update_interval']:
                return

            # Cleanup old detections
            self._cleanup_old_detections()
            
            if self.debug:
                logging.debug(f"[DeauthSniffer] Checking {len(access_points)} access points")
            
            new_detections = []
            for ap in access_points:
                if not isinstance(ap, dict):
                    continue

                # Check for deauth frames
                is_deauth = False
                mac = ap.get('mac')
                
                if not mac or mac in self.whitelist:
                    continue

                # Check various fields for deauth indicators
                for key, value in ap.items():
                    if isinstance(value, str) and ('deauth' in value.lower() or 'deauthentication' in value.lower()):
                        is_deauth = True
                        break
                    elif isinstance(value, dict) and ('type' in value and ('deauth' in value['type'].lower() or 'deauthentication' in value['type'].lower())):
                        is_deauth = True
                        break

                if is_deauth and mac:
                    with self.lock:
                        if mac not in self.detected_bssids:
                            self.detected_bssids[mac] = current_time
                            new_detections.append(mac)
                            self._log_detection(mac, ap)

            # Update UI only if there are new detections
            if new_detections:
                try:
                    view = agent.view()
                    # Set the face to angry
                    view.set('face', faces.ANGRY)
                    
                    # Create a temporary message
                    self.current_message = f"Deauth detected: {len(new_detections)} new frames"
                    self.message_expiry = current_time + self.options['message_duration']
                    
                    # Add the message to the UI
                    view.add_element('deauth_status', 
                                   LabeledValue(color=BLACK, 
                                              label='', 
                                              value=self.current_message,
                                              position=(145, 65),  # Position above lvl and exp, below agent messages
                                              label_font=fonts.Small,
                                              text_font=fonts.Small))
                    
                    self.last_ui_update = current_time
                except Exception as e:
                    logging.error(f"[DeauthSniffer] Error updating UI: {str(e)}")

        except Exception as e:
            logging.error(f"[DeauthSniffer] Error in wifi_update: {str(e)}")
            if self.debug:
                logging.debug(f"[DeauthSniffer] Access points data: {access_points}") 