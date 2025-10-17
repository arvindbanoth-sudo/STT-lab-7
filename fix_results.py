import json
import csv
import pandas as pd
from collections import defaultdict
import re

# CWE Top 25 2024
CWE_TOP_25 = {
    'CWE-787', 'CWE-79', 'CWE-89', 'CWE-416', 'CWE-78', 
    'CWE-20', 'CWE-125', 'CWE-22', 'CWE-352', 'CWE-434',
    'CWE-306', 'CWE-190', 'CWE-502', 'CWE-77', 'CWE-119',
    'CWE-798', 'CWE-918', 'CWE-362', 'CWE-269', 'CWE-862',
    'CWE-276', 'CWE-287', 'CWE-200', 'CWE-476', 'CWE-522'
}

def clean_cwe_id(cwe_string):
    """Extract clean CWE ID from various formats"""
    if not cwe_string or pd.isna(cwe_string):
        return None
    
    cwe_string = str(cwe_string)
    
    # Handle different formats
    if cwe_string.startswith('CWE-'):
        # Extract just the CWE-ID part (e.g., "CWE-79" from "CWE-79: Improper Neutralization...")
        match = re.match(r'(CWE-\d+)', cwe_string)
        if match:
            return match.group(1)
    
    # Handle numeric values
    if cwe_string.isdigit():
        return f"CWE-{cwe_string}"
    
    return None

def process_semgrep_json(file_path, project, tool):
    """Process Semgrep JSON results with proper CWE extraction"""
    results = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        cwe_counts = defaultdict(int)
        
        for finding in data.get('results', []):
            metadata = finding.get('extra', {}).get('metadata', {})
            cwes = metadata.get('cwe', [])
            
            if not cwes:
                continue
                
            # Handle both string and list formats
            if isinstance(cwes, str):
                clean_cwe = clean_cwe_id(cwes)
                if clean_cwe:
                    cwe_counts[clean_cwe] += 1
            elif isinstance(cwes, list):
                for cwe_item in cwes:
                    clean_cwe = clean_cwe_id(cwe_item)
                    if clean_cwe:
                        cwe_counts[clean_cwe] += 1
        
        for cwe_id, count in cwe_counts.items():
            results.append({
                'Project_name': project,
                'Tool_name': tool,
                'CWE_ID': cwe_id,
                'Number_of_Findings': count,
                'Is_In_CWE_Top_25': 'Yes' if cwe_id in CWE_TOP_25 else 'No'
            })
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return results

def process_bandit_json(file_path, project, tool):
    """Process Bandit JSON results with proper CWE mapping"""
    results = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        cwe_counts = defaultdict(int)
        
        for finding in data.get('results', []):
            # Bandit stores CWE information in issue_cwe field
            cwe_info = finding.get('issue_cwe', {})
            
            if isinstance(cwe_info, dict):
                cwe_id = cwe_info.get('id')
                if cwe_id:
                    clean_cwe = clean_cwe_id(cwe_id)
                    if clean_cwe:
                        cwe_counts[clean_cwe] += 1
            elif isinstance(cwe_info, str):
                clean_cwe = clean_cwe_id(cwe_info)
                if clean_cwe:
                    cwe_counts[clean_cwe] += 1
        
        # If no CWEs found, categorize by Bandit test ID
        if not cwe_counts:
            bandit_counts = defaultdict(int)
            for finding in data.get('results', []):
                test_id = finding.get('test_id', 'Unknown')
                bandit_counts[test_id] += 1
            
            for test_id, count in bandit_counts.items():
                results.append({
                    'Project_name': project,
                    'Tool_name': tool,
                    'CWE_ID': f'Bandit-{test_id}',
                    'Number_of_Findings': count,
                    'Is_In_CWE_Top_25': 'No'
                })
        else:
            for cwe_id, count in cwe_counts.items():
                results.append({
                    'Project_name': project,
                    'Tool_name': tool,
                    'CWE_ID': cwe_id,
                    'Number_of_Findings': count,
                    'Is_In_CWE_Top_25': 'Yes' if cwe_id in CWE_TOP_25 else 'No'
                })
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return results

def process_flawfinder_csv(file_path, project, tool):
    """Process Flawfinder CSV results with accurate counting"""
    results = []
    cwe_counts = defaultdict(int)
    
    try:
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            for row_num, row in enumerate(reader):
                if row_num == 0 or len(row) < 4:  # Skip header and invalid rows
                    continue
                
                cwe_part = row[2].strip() if len(row) > 2 else ''
                if cwe_part.isdigit():
                    cwe_id = f"CWE-{cwe_part}"
                    cwe_counts[cwe_id] += 1
        
        for cwe_id, count in cwe_counts.items():
            results.append({
                'Project_name': project,
                'Tool_name': tool,
                'CWE_ID': cwe_id,
                'Number_of_Findings': count,
                'Is_In_CWE_Top_25': 'Yes' if cwe_id in CWE_TOP_25 else 'No'
            })
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    
    return results

def clean_existing_csv(input_file, output_file):
    """Clean and normalize an existing CSV file"""
    df = pd.read_csv(input_file)
    
    # Clean CWE IDs
    df['CWE_ID'] = df['CWE_ID'].apply(clean_cwe_id)
    
    # Remove rows with invalid CWE IDs
    df = df[df['CWE_ID'].notna()]
    
    # Group by project, tool, and clean CWE ID to sum findings
    cleaned_df = df.groupby(['Project_name', 'Tool_name', 'CWE_ID']).agg({
        'Number_of_Findings': 'sum',
        'Is_In_CWE_Top_25': 'first'
    }).reset_index()
    
    # Update Top 25 status based on clean CWE IDs
    cleaned_df['Is_In_CWE_Top_25'] = cleaned_df['CWE_ID'].apply(
        lambda x: 'Yes' if x in CWE_TOP_25 else 'No'
    )
    
    cleaned_df.to_csv(output_file, index=False)
    return cleaned_df

# Option 1: Clean your existing CSV
print("Cleaning existing CSV...")
cleaned_results = clean_existing_csv('consolidated_results.csv', 'cleaned_consolidated_results.csv')

print(f"Original unique CWEs: {len(pd.read_csv('consolidated_results.csv')['CWE_ID'].unique())}")
print(f"Cleaned unique CWEs: {len(cleaned_results['CWE_ID'].unique())}")
print(f"Total findings: {cleaned_results['Number_of_Findings'].sum()}")

# Option 2: Process your raw tool outputs again
# Uncomment below if you want to reprocess from original tool outputs
"""
all_results = []

# Process each project and tool
all_results.extend(process_semgrep_json('tensorflow_semgrep.json', 'tensorflow', 'semgrep'))
all_results.extend(process_bandit_json('tensorflow_bandit.json', 'tensorflow', 'bandit'))
all_results.extend(process_flawfinder_csv('tensorflow_flawfinder.csv', 'tensorflow', 'flawfinder'))

# Repeat for other projects...

# Create final DataFrame
final_df = pd.DataFrame(all_results)
final_df.to_csv('proper_consolidated_results.csv', index=False)
"""
