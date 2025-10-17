import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from itertools import combinations

# Load your cleaned data
df = pd.read_csv('cleaned_consolidated_results.csv')

print("="*60)
print("PART 2: PAIRWISE AGREEMENT (IoU) ANALYSIS")
print("="*60)

# Get tools and their CWE sets
tools = df['Tool_name'].unique()
tool_cwe_sets = {}

for tool in tools:
    tool_cwe_sets[tool] = set(df[df['Tool_name'] == tool]['CWE_ID'])

print(f"Tools analyzed: {list(tools)}")

# Step 1: Compute IoU for each tool pair
def calculate_iou(set1, set2):
    """Calculate Intersection over Union (Jaccard Index)"""
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union if union > 0 else 0

print("\n1. COMPUTING IoU VALUES FOR TOOL PAIRS:")

# Create IoU matrix
iou_matrix = pd.DataFrame(index=tools, columns=tools, dtype=float)

for tool1 in tools:
    for tool2 in tools:
        iou_value = calculate_iou(tool_cwe_sets[tool1], tool_cwe_sets[tool2])
        iou_matrix.loc[tool1, tool2] = round(iou_value, 3)

print("\nIoU Matrix:")
print(iou_matrix)

# Step 2: Detailed pair analysis
print("\n2. DETAILED TOOL PAIR ANALYSIS:")
tool_pairs = list(combinations(tools, 2))

for tool1, tool2 in tool_pairs:
    set1 = tool_cwe_sets[tool1]
    set2 = tool_cwe_sets[tool2]
    
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    only_tool1 = set1 - set2
    only_tool2 = set2 - set1
    iou_value = iou_matrix.loc[tool1, tool2]
    
    print(f"\n   {tool1} vs {tool2}:")
    print(f"   - IoU: {iou_value:.3f}")
    print(f"   - Common CWEs: {len(intersection)}")
    print(f"   - Unique to {tool1}: {len(only_tool1)}")
    print(f"   - Unique to {tool2}: {len(only_tool2)}")
    print(f"   - Total unique CWEs in union: {len(union)}")
    
    if intersection:
        print(f"   - Shared CWEs: {sorted(intersection)}")

# Step 3: Find tool combination that maximizes CWE coverage
print("\n3. MAXIMIZING CWE COVERAGE ANALYSIS:")

max_coverage = 0
best_pair = None
best_combined_cwes = None

for tool1, tool2 in tool_pairs:
    combined_cwes = tool_cwe_sets[tool1].union(tool_cwe_sets[tool2])
    coverage = len(combined_cwes)
    
    if coverage > max_coverage:
        max_coverage = coverage
        best_pair = (tool1, tool2)
        best_combined_cwes = combined_cwes

print(f"   Best tool combination: {best_pair}")
print(f"   Maximum CWE coverage: {max_coverage} unique CWEs")
print(f"   Combined CWE set: {sorted(best_combined_cwes)}")

# Compare with all three tools combined
all_tools_combined = set().union(*[tool_cwe_sets[tool] for tool in tools])
print(f"   All three tools combined: {len(all_tools_combined)} unique CWEs")

improvement = len(all_tools_combined) - max_coverage
if improvement > 0:
    print(f"   Additional coverage from third tool: {improvement} CWEs")
else:
    print(f"   Two tools achieve maximum coverage")

# Step 4: Visualize IoU Matrix without seaborn
print("\n4. GENERATING IoU VISUALIZATION...")

plt.figure(figsize=(8, 6))

# Create manual heatmap using imshow
matrix_values = iou_matrix.astype(float).values

im = plt.imshow(matrix_values, cmap='YlOrRd', aspect='auto', vmin=0, vmax=1)

# Add text annotations
for i in range(len(tools)):
    for j in range(len(tools)):
        text = plt.text(j, i, f'{matrix_values[i, j]:.3f}',
                       ha="center", va="center", color="black", fontweight='bold')

# Set labels
plt.xticks(range(len(tools)), tools, rotation=45)
plt.yticks(range(len(tools)), tools)
plt.title('Tool Pairwise IoU Matrix\n(Intersection over Union)', fontsize=14, fontweight='bold')

# Add colorbar
cbar = plt.colorbar(im, shrink=0.8)
cbar.set_label('IoU Value', rotation=270, labelpad=15)

plt.tight_layout()
plt.savefig('iou_matrix_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

# Step 5: Interpretation and Insights
print("\n5. IoU MATRIX INTERPRETATION:")
print("   IoU Value Ranges:")
print("   - 0.0-0.1: Very low agreement (tools detect completely different vulnerabilities)")
print("   - 0.1-0.3: Low agreement (some overlap but mostly different)")
print("   - 0.3-0.5: Moderate agreement (significant overlap)")
print("   - 0.5-0.7: High agreement (mostly similar detection patterns)")
print("   - 0.7-1.0: Very high agreement (tools detect nearly identical vulnerabilities)")

print("\n6. KEY INSIGHTS:")
print(f"   - Best complementary tools: {best_pair} (maximizes CWE coverage)")
print(f"   - Total unique CWEs detected by all tools: {len(all_tools_combined)}")

# Analyze tool diversity
for tool1, tool2 in tool_pairs:
    iou_val = iou_matrix.loc[tool1, tool2]
    if iou_val < 0.2:
        print(f"   - {tool1} & {tool2}: HIGH diversity (IoU: {iou_val:.3f}) - Good for comprehensive scanning")
    elif iou_val > 0.5:
        print(f"   - {tool1} & {tool2}: LOW diversity (IoU: {iou_val:.3f}) - Redundant detection")

print("\n7. RECOMMENDATIONS:")
print(f"   - For maximum CWE coverage: Use {best_pair[0]} + {best_pair[1]}")
print(f"   - For comprehensive analysis: Use all three tools")
print("   - Consider tool diversity when selecting multiple tools")

# Save IoU matrix to CSV
iou_matrix.to_csv('iou_matrix_results.csv')
print(f"\n8. RESULTS SAVED:")
print("   - iou_matrix_analysis.png")
print("   - iou_matrix_results.csv")

print("\n" + "="*60)
print("PART 2 COMPLETED: Pairwise Agreement (IoU) Analysis")
print("="*60)
