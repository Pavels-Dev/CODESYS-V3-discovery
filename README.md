# CODESYS-V3-scan
This Nmap dissector is designed to identify Programmable Logic Controllers (PLC) that use CORDESYS V3 and extract comprehensive information about them using the CODESYS discovery Function.
## Instalation
Download the .nse file
Nmap scripts should be placed in the Nmap scripts directory. The location of this directory varies depending on your operating system:
- Linux and macOS: Usually, it's located at /usr/local/share/nmap/scripts/ or /usr/share/nmap/scripts/, depending on how Nmap was installed.
## Usage
To use the script you need to run it as sudo enter give it the interface as a argument and scan for the port 6626
```bash
sudo nmap --script codesysv3-scan.nse
```
## Example Output
```bash
PORT     STATE SERVICE
6626/tcp open  wago-service
| codesysv3-scan: 
|   
|     Device_Name = CODESYS Control for Raspberry Pi SL
|   
|     Device_Vendor: CODESYS GmbH
|   
|     Node_Name: raspberrypi
|   
|     Firmware: V4.11.0.0
|   
|     Serualnumber: X
|   
|     Max_Channels: 4
|   
|     Target_type: 4102
|
|     Target_ID: 16
|     
|     Target_type: 4102
|
|     NS_Client_Version: 400
|
|_    MessageID: 000084b4
MAC Address: 00:30:DE:42:AD:53 (Wago Kontakttechnik Gmbh)
```

## Disclaimer:

This tool is designed for information technology security purposes only. It should be used exclusively on networks and systems where explicit authorization has been obtained. Unauthorized scanning of networks and systems is illegal and unethical. Users must ensure they have written permission from the rightful owners of the systems to be scanned. We are not responsible for any misuse of this tool, nor for any consequences that result from such misuse. It is the user's responsibility to adhere to all applicable laws and regulations related to network scanning and data security. Use this tool at your own risk.

## Tested on
- CODESYS for Control for Raspberry Pi
- WAGO 750-8202 PFC200
