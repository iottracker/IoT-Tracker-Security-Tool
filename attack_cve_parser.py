import re
import os
from typing import Dict, List

def parse_attack_cve_file(file_path: str) -> Dict[str, List[Dict]]:
    """
    Parses attack-CVE mapping text files into structured data
    
    Args:
        file_path: Path to the text file containing attack->CVE mappings
        
    Returns: 
        Dictionary {attack_type: [{cve_id: str, description: str}]}
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file format is invalid
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Attack-CVE mapping file not found: {file_path}")
    
    # Modified regex pattern to match attack sections
    attack_section_pattern = re.compile(
        r"🔍 Fetching CVEs for: (.*?)(?=\s*🔍|\Z)",
        re.DOTALL
    )
    
    # Modified regex to match CVEs with bullet points
    cve_pattern = re.compile(
        r"➤\s+(CVE-\d+-\d+):(.*?)(?=\s*➤|\Z)",
        re.DOTALL
    )

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Fallback to latin-1 if UTF-8 fails
        with open(file_path, 'r', encoding='latin-1') as f:
            content = f.read()

    attack_map = {}
    
    # Split content into attack sections
    for attack_section_match in attack_section_pattern.finditer(content):
        # The full attack section with name and possible description
        attack_section = attack_section_match.group(1).strip()
        
        # Extract just the attack name (before any parentheses)
        if '(' in attack_section:
            attack_name = attack_section.split('(')[0].strip()
        else:
            attack_name = attack_section
            
        # Normalize attack name for consistency
        normalized_attack_name = attack_name.replace(' ', '_').replace('-', '_').upper()
        
        # Get the full content of this section
        section_start = attack_section_match.start()
        section_end = attack_section_match.end()
        next_section = content.find("🔍 Fetching CVEs for:", section_end)
        if next_section == -1:
            next_section = len(content)
        
        section_content = content[section_start:next_section]
        
        # Find all CVEs in this section
        cves = []
        for cve_match in cve_pattern.finditer(section_content):
            cve_id = cve_match.group(1).strip()
            desc = cve_match.group(2).strip().replace('\n', ' ')
            
            # Additional validation for CVE ID format
            if not re.match(r'^CVE-\d{4}-\d{1,7}$', cve_id):
                print(f"Warning: Potentially invalid CVE ID format: {cve_id}")
            
            cves.append({
                'cve_id': cve_id,
                'description': desc
            })
        
        # Store the attack and its CVEs
        attack_map[normalized_attack_name] = cves
        
        # Debug output to help diagnose matching issues
        print(f"Processed attack: {normalized_attack_name} - Found {len(cves)} CVEs")

    if not attack_map:
        raise ValueError("No valid attack-CVE mappings found in the file")
    
    # Print summary of all attacks found
    print(f"Successfully loaded {len(attack_map)} attack types:")
    for attack in sorted(attack_map.keys()):
        print(f"  - {attack}: {len(attack_map[attack])} CVEs")
        
    return attack_map