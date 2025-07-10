# display-password shows recently cracked passwords on the pwnagotchi display 
#
# This plugin is a modified version of the original display-password plugin by @nagy_craig
# https://github.com/nagy-craig/pwnagotchi-plugins/blob/master/display-password.py
#
# The original plugin only shows the most recent password from the potfile, this plugin shows the most recent password from any potfile
#
# The original plugin only shows the password, this plugin shows the password and the source of the password
#
#
###############################################################
#
# Updates to the famous @nagy_craig code , now handles no files found
#
###############################################################
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts
import pwnagotchi.plugins as plugins
import pwnagotchi
import logging
import os
import time


class DisplayPassword(plugins.Plugin):
    __author__ = 'ZeroDumb'
    __version__ = '1.1.0'
    __license__ = 'GPL3'
    __description__ = 'A plugin to display recently cracked passwords from multiple sources'

    def __init__(self):
        self.potfiles = [
            '/home/pi/handshakes/quickdic.cracked.potfile',
            '/home/pi/handshakes/wpa-sec.cracked.potfile'
        ]

    def on_loaded(self):
        logging.info("display-password loaded")

    def _get_last_line_from_file(self, file_path):
        """Get the last line from a file, handling various formats"""
        try:
            if not os.path.exists(file_path):
                return None, 0
                
            # Get file modification time
            mtime = os.path.getmtime(file_path)
            
            # Read the last line
            with open(file_path, 'r') as file:
                lines = file.readlines()
                if not lines:
                    return None, mtime
                    
                last_line = lines[-1].strip()
                if not last_line:
                    return None, mtime
                    
                return last_line, mtime
                
        except Exception as e:
            logging.debug(f'[display-password] Error reading {file_path}: {str(e)}')
            return None, 0

    def _parse_potfile_line(self, line):
        """Parse potfile line and extract network info and password"""
        try:
            # Split by colon to get fields
            parts = line.split(':')
            
            if len(parts) >= 4:
                # Standard format: bssid:station_mac:ssid:password
                bssid = parts[0]
                station_mac = parts[1]
                ssid = parts[2]
                password = parts[3]
                
                # Handle extended format with GPS data
                gps_info = ""
                if len(parts) >= 6:
                    lat = parts[4] if parts[4] else ""
                    lon = parts[5] if parts[5] else ""
                    if lat and lon:
                        gps_info = f" ({lat},{lon})"
                
                # Format the display string
                if ssid and ssid != "Unknown":
                    result = f"{ssid} - {password}{gps_info}"
                else:
                    result = f"{bssid} - {password}{gps_info}"
                    
                return result
            else:
                return "Invalid format"
                
        except Exception as e:
            logging.debug(f'[display-password] Error parsing line: {str(e)}')
            return "Parse error"

    def _get_most_recent_password(self):
        """Get the most recent password from any potfile"""
        most_recent_line = None
        most_recent_time = 0
        most_recent_source = None
        
        for potfile in self.potfiles:
            line, mtime = self._get_last_line_from_file(potfile)
            if line and mtime > most_recent_time:
                most_recent_line = line
                most_recent_time = mtime
                most_recent_source = potfile
        
        if most_recent_line:
            parsed_result = self._parse_potfile_line(most_recent_line)
            logging.debug(f'[display-password] Most recent from {most_recent_source}: {parsed_result}')
            return parsed_result
        else:
            return "No cracked passwords"

    def on_ui_setup(self, ui):
        if ui.is_waveshare_v2():
            h_pos = (0, 95)
            v_pos = (180, 61)
        elif ui.is_waveshare_v4():
            h_pos = (0, 95)
            v_pos = (180, 61)
        elif ui.is_waveshare_v3():
            h_pos = (0, 95)
            v_pos = (180, 61)  
        elif ui.is_waveshare_v1():
            h_pos = (0, 95)
            v_pos = (170, 61)
        elif ui.is_waveshare144lcd():
            h_pos = (0, 92)
            v_pos = (78, 67)
        elif ui.is_inky():
            h_pos = (0, 83)
            v_pos = (165, 54)
        elif ui.is_waveshare27inch():
            h_pos = (0, 153)
            v_pos = (216, 122)
        else:
            h_pos = (0, 91)
            v_pos = (180, 61)

        if self.options['orientation'] == "vertical":
            ui.add_element('display-password', LabeledValue(color=BLACK, label='', value='',
                                                   position=v_pos,
                                                   label_font=fonts.Bold, text_font=fonts.Small))
        else:
            # default to horizontal
            ui.add_element('display-password', LabeledValue(color=BLACK, label='', value='',
                                                   position=h_pos,
                                                   label_font=fonts.Bold, text_font=fonts.Small))

    def on_unload(self, ui):
        with ui._lock:
            ui.remove_element('display-password')

    def on_ui_update(self, ui):
        # Get the most recent password from any potfile
        result = self._get_most_recent_password()
        ui.set('display-password', result)
