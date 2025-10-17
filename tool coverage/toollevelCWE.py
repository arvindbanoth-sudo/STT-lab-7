import pandas as pd
import matplotlib.pyplot as plt

# Load your cleaned data
df = pd.read_csv('cleaned_consolidated_results.csv')

# CWE Top 25 2024
CWE_TOP_25 = {
    'CWE-79', 'CWE-787', 'CWE-20', 'CWE-125', 'CWE-78', 
    'CWE-89', 'CWE-416', 'CWE-22', 'CWE-352', 'CWE-434',
    'CWE-306', 'CWE-190', 'CWE-502', 'CWE-77', 'CWE-119',
    'CWE-798', 'CWE-918', 'CWE-362', 'CWE-269', 'CWE-862',
    'CWE-276', 'CWE-287', 'CWE-200', 'CWE-476', 'CWE-522'
}

print("="*60)
print("PART 1: TOOL-LEVEL CWE COVERAGE ANALYSIS")
print("="*60)

# Step 1: Extract sets of CWE IDs detected by each tool
tools = df['Tool_name'].unique()
tool_cwe_sets = {}
coverage_data = []

print("\n1. EXTRACTING CWE ID SETS FOR EACH TOOL:")
for tool in tools:
    tool_cwes = set(df[df['Tool_name'] == tool]['CWE_ID'])
    tool_cwe_sets[tool] = tool_cwes
    
    print(f"   {tool}: {len(tool_cwes)} unique CWEs")
    print(f"   Detected CWEs: {sorted(tool_cwes)}")

# Step 2: Compute Top 25 CWE coverage percentage for each tool
print("\n2. TOP 25 CWE COVERAGE ANALYSIS:")
for tool in tools:
    tool_cwes = tool_cwe_sets[tool]
    top25_detected = tool_cwes.intersection(CWE_TOP_25)
    coverage_percentage = (len(top25_detected) / len(CWE_TOP_25)) * 100
    
    coverage_data.append({
        'Tool': tool,
        'Total_Unique_CWEs': len(tool_cwes),
        'Top25_CWEs_Detected': len(top25_detected),
        'Coverage_Percentage': coverage_percentage,
        'Detected_Top25_CWEs': sorted(top25_detected)
    })
    
    print(f"\n   {tool}:")
    print(f"   - Total Unique CWEs: {len(tool_cwes)}")
    print(f"   - Top 25 CWEs Detected: {len(top25_detected)}")
    print(f"   - Top 25 Coverage: {coverage_percentage:.1f}%")
    print(f"   - Specific Top 25 CWEs: {sorted(top25_detected)}")

# Step 3: Visualize coverage
print("\n3. GENERATING COVERAGE VISUALIZATIONS...")

# Create coverage DataFrame for plotting
coverage_df = pd.DataFrame(coverage_data)

# Plot 1: Top 25 CWE Coverage Percentage
plt.figure(figsize=(12, 5))

plt.subplot(1, 2, 1)
bars = plt.bar(coverage_df['Tool'], coverage_df['Coverage_Percentage'], 
               color=['#ff6b6b', '#4ecdc4', '#45b7d1'], alpha=0.8)
plt.title('Top 25 CWE Coverage Percentage by Tool', fontsize=14, fontweight='bold')
plt.xlabel('Security Tool')
plt.ylabel('Coverage Percentage (%)')
plt.xticks(rotation=45)
plt.grid(axis='y', alpha=0.3)

# Add value labels on bars
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2., height + 1,
             f'{height:.1f}%', ha='center', va='bottom', fontweight='bold')

# Plot 2: Total vs Top 25 CWEs Detected
plt.subplot(1, 2, 2)
x = range(len(coverage_df))
width = 0.35

plt.bar(x, coverage_df['Total_Unique_CWEs'], width, label='Total CWEs', 
        color='lightblue', alpha=0.7)
plt.bar([i + width for i in x], coverage_df['Top25_CWEs_Detected'], width, 
        label='Top 25 CWEs', color='coral', alpha=0.7)

plt.title('CWE Detection: Total vs Top 25', fontsize=14, fontweight='bold')
plt.xlabel('Security Tool')
plt.ylabel('Number of CWEs')
plt.xticks([i + width/2 for i in x], coverage_df['Tool'])
plt.legend()
plt.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig('tool_cwe_coverage_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

# Summary statistics
print("\n4. COVERAGE ANALYSIS SUMMARY:")
print(f"   Total possible Top 25 CWEs: {len(CWE_TOP_25)}")
print(f"   Tools analyzed: {len(tools)}")
print(f"   Overall Top 25 coverage range: {coverage_df['Coverage_Percentage'].min():.1f}% - {coverage_df['Coverage_Percentage'].max():.1f}%")

best_coverage_tool = coverage_df.loc[coverage_df['Coverage_Percentage'].idxmax()]
print(f"   Best Top 25 coverage: {best_coverage_tool['Tool']} ({best_coverage_tool['Coverage_Percentage']:.1f}%)")

# Save results to CSV
coverage_df.to_csv('tool_coverage_results.csv', index=False)
print(f"\n5. RESULTS SAVED:")
print("   - tool_cwe_coverage_analysis.png")
print("   - tool_coverage_results.csv")

print("\n" + "="*60)
print("PART 1 COMPLETED: Tool-Level CWE Coverage Analysis")
print("="*60)
