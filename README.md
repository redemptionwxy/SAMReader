# SAMReader
Python Script to Read SAM file from Windows

The Windows Security Account Manager (SAM) file is a registry hive (%SystemRoot%/System32/config/SAM) that stores local user account security information
primarily used for offline password cracking and credential dumping. It contains usernames, group memberships, Security Identifiers (SIDs), and LM/NTLM password hashes.

1. Download SAM file from target machine using FTK Imager 
2. Use the script by typing: python SAMReader SAM
