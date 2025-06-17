import logging
import os
import shutil
import time
import pwnagotchi.plugins as plugins
from pwnagotchi.utils import extract_from_pcap, WifiInfo
import pwnagotchi.ui.faces as faces

class WPA3Parse(plugins.Plugin):
    __author__ = 'ZeroDumb'
    __version__ = '1.3.0'
    __license__ = 'GPL3'
    __description__ = 'Logs WPA3 handshake captures, copies them (and optionally GPS/geo files), animates the face, and supports whitelisting and false positive reduction.'

    def __init__(self):
        self.copy_gps_geo = True
        self.whitelist = []

    def on_loaded(self):
        # Read options from config.toml
        self.copy_gps_geo = self.options.get('copy_gps_geo', True)
        self.whitelist = self.options.get('whitelist', [])
        logging.info(f"[WPA3Parse] Plugin loaded. copy_gps_geo={self.copy_gps_geo}, whitelist={self.whitelist}")

    def on_handshake(self, agent, filename, access_point, client_station):
        try:
            # False positive reduction: check both pcap and access_point for WPA3/SAE
            info = extract_from_pcap(filename, [WifiInfo.ENCRYPTION])
            encryption = info.get(WifiInfo.ENCRYPTION, [])
            ap_enc = []
            ap_bssid = None
            ap_ssid = None
            if isinstance(access_point, dict):
                ap_enc = access_point.get('encryption', [])
                ap_bssid = access_point.get('mac', None)
                ap_ssid = access_point.get('hostname', None)
            else:
                ap_bssid = access_point
            # Whitelist check (by SSID or BSSID)
            if ap_bssid and any(w.lower() in str(ap_bssid).lower() for w in self.whitelist):
                logging.info(f"[WPA3Parse] Skipping whitelisted BSSID: {ap_bssid}")
                return
            if ap_ssid and any(w.lower() in str(ap_ssid).lower() for w in self.whitelist):
                logging.info(f"[WPA3Parse] Skipping whitelisted SSID: {ap_ssid}")
                return
            # False positive reduction: require both pcap and AP encryption to indicate WPA3/SAE
            is_wpa3 = any(enc.upper() in ["WPA3", "SAE"] for enc in encryption) and any(enc.upper() in ["WPA3", "SAE"] for enc in ap_enc)
            if is_wpa3:
                logging.info(f"[WPA3Parse] WPA3 handshake captured: {filename}, AP: {ap_ssid or ap_bssid}, Client: {client_station}, Encryption: {encryption}")
                wpa3_dir = "/home/pi/handshakes/wpa3/"
                os.makedirs(wpa3_dir, exist_ok=True)
                dest_file = os.path.join(wpa3_dir, os.path.basename(filename))
                shutil.copy2(filename, dest_file)
                logging.info(f"[WPA3Parse] Copied WPA3 handshake to {dest_file}")
                # Optionally copy GPS/geo files
                if self.copy_gps_geo:
                    for ext in [".gps.json", ".geo.json"]:
                        meta_file = filename.replace('.pcap', ext)
                        if os.path.exists(meta_file):
                            shutil.copy2(meta_file, os.path.join(wpa3_dir, os.path.basename(meta_file)))
                            logging.info(f"[WPA3Parse] Copied {ext} to {wpa3_dir}")
                # Animate the face: alternate between look_r_happy and look_l_happy
                view = agent.view()
                for _ in range(3):
                    view.set('face', faces.LOOK_R_HAPPY)
                    view.update()
                    time.sleep(0.4)
                    view.set('face', faces.LOOK_L_HAPPY)
                    view.update()
                    time.sleep(0.4)
            else:
                logging.debug(f"[WPA3Parse] Handshake is not WPA3: {filename}, Encryption: {encryption}, AP encryption: {ap_enc}")
        except Exception as e:
            logging.error(f"[WPA3Parse] Error processing handshake {filename}: {e}")

    def on_unload(self, ui):
        logging.info("[WPA3Parse] Plugin unloaded.") 