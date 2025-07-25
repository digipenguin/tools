#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys

def extract_references_by_sid(rules_file_path, target_sid):
    """
    Extract reference information from Suricata rules file by SID
    
    Args:
        rules_file_path (str): Path to the rules file
        target_sid (str): Target SID number
    
    Returns:
        list: List of references
    """
    references = []
    
    try:
        with open(rules_file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Find rule containing target SID
                sid_match = re.search(r'sid:\s*(\d+)', line)
                if sid_match and sid_match.group(1) == str(target_sid):
                    # Found matching rule, extract all references
                    ref_matches = re.findall(r'reference:\s*([^;]+)', line)
                    
                    for ref in ref_matches:
                        ref = ref.strip()
                        references.append(process_reference(ref))
                    
                    break  # Exit loop after finding the rule
                    
    except FileNotFoundError:
        print(f"Error: Rules file not found: {rules_file_path}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []
    
    return references

def process_reference(reference):
    """
    Process reference information, add VirusTotal links for hash values
    
    Args:
        reference (str): Original reference string
    
    Returns:
        str: Processed reference string
    """
    # Split type and value
    if ',' in reference:
        ref_type, ref_value = reference.split(',', 1)
        ref_type = ref_type.strip()
        ref_value = ref_value.strip()
    else:
        return reference
    
    # If it's URL type, return the URL directly
    if ref_type.lower() == 'url':
        # Ensure URL has proper protocol
        if not ref_value.startswith(('http://', 'https://')):
            ref_value = 'http://' + ref_value
        return ref_value
    
    # Check for various hash formats
    hash_types = ['md5', 'sha1', 'sha256', 'sha512']
    
    if ref_type.lower() in hash_types:
        return f"https://www.virustotal.com/gui/file/{ref_value}"
    
    # Check if value looks like a hash (32-char MD5, 40-char SHA1, 64-char SHA256, etc.)
    if re.match(r'^[a-fA-F0-9]{32}$', ref_value):  # MD5
        return f"https://www.virustotal.com/gui/file/{ref_value}"
    elif re.match(r'^[a-fA-F0-9]{40}$', ref_value):  # SHA1
        return f"https://www.virustotal.com/gui/file/{ref_value}"
    elif re.match(r'^[a-fA-F0-9]{64}$', ref_value):  # SHA256
        return f"https://www.virustotal.com/gui/file/{ref_value}"
    elif re.match(r'^[a-fA-F0-9]{128}$', ref_value):  # SHA512
        return f"https://www.virustotal.com/gui/file/{ref_value}"
    
    # If not a special type, return original format
    return f"{ref_type}: {ref_value}"

def main():
    # Default rules file path
    default_rules_path = "/var/lib/suricata/rules/suricata.rules"
    
    if len(sys.argv) < 2:
        print("Usage: python suricata_ref_extractor.py <SID> [rules_file_path]")
        print(f"Default rules file path: {default_rules_path}")
        sys.exit(1)
    
    target_sid = sys.argv[1]
    rules_path = sys.argv[2] if len(sys.argv) > 2 else default_rules_path
    
    print(f"Searching for SID: {target_sid}")
    print(f"Rules file: {rules_path}")
    print("-" * 50)
    
    references = extract_references_by_sid(rules_path, target_sid)
    
    if references:
        print(f"Found reference information for SID {target_sid}:")
        for i, ref in enumerate(references, 1):
            print(f"{i}. {ref}")
    else:
        print(f"SID {target_sid} not found or no reference information available")

if __name__ == "__main__":
    main()

# Convenience function for use in other programs
def get_references_by_sid(sid, rules_file="/var/lib/suricata/rules/suricata.rules"):
    """
    Convenience function: Get reference list by SID
    
    Args:
        sid (str or int): SID number
        rules_file (str): Rules file path
    
    Returns:
        list: List of references
    """
    return extract_references_by_sid(rules_file, str(sid))

# Test function using provided sample data
def test_with_sample_data():
    """
    Test using the provided sample Suricata rules
    """
    sample_rules = """
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS NetClassifieds Premium Edition SQL Injection Attempt -- ViewCat.php s_user_id INSERT"; flow:established,to_server; http.uri; content:"/ViewCat.php?"; nocase; content:"s_user_id="; nocase; content:"INSERT"; nocase; content:"INTO"; distance:0; nocase; reference:cve,CVE-2007-3354; reference:url,www.securityfocus.com/bid/24584; classtype:web-application-attack; sid:2006549; rev:9; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, confidence Medium, signature_severity Major, tag SQL_Injection, updated_at 2020_04_17, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS NetVIOS Portal SQL Injection Attempt -- page.asp NewsID SELECT"; flow:established,to_server; http.uri; content:"/News/page.asp?"; nocase; content:"NewsID="; nocase; content:"SELECT"; nocase; content:"FROM"; nocase; distance:0; reference:cve,CVE-2007-1566; reference:url,www.exploit-db.com/exploits/3520/; classtype:web-application-attack; sid:2004158; rev:8; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, confidence Medium, signature_severity Major, tag SQL_Injection, updated_at 2020_04_17, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application;)
"""
    
    # Write sample data to temporary file for testing
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as temp_file:
        temp_file.write(sample_rules)
        temp_file_path = temp_file.name
    
    try:
        print("=== Sample Test ===")
        
        # Test SID 2006549
        print("\nTesting SID 2006549:")
        refs = extract_references_by_sid(temp_file_path, "2006549")
        for ref in refs:
            print(f"  - {ref}")
        
        # Test SID 2004158  
        print("\nTesting SID 2004158:")
        refs = extract_references_by_sid(temp_file_path, "2004158")
        for ref in refs:
            print(f"  - {ref}")
            
    finally:
        # Clean up temporary file
        os.unlink(temp_file_path)

if __name__ == "__main__":
    # If no command line arguments, run test
    if len(sys.argv) == 1:
        test_with_sample_data()
    else:
        main()
