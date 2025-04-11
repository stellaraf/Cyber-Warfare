Port Scanning
sudo nmap -Pn -T5 -p- --open 10.3.32.11

Service Enumeration
sudo nmap -sC -sV -r -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -T5 10.3.32.11 --reason --open