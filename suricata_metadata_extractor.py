import re
metadata_dict = {}
with open("/opt/wsp.d/volume0/rules-latest/rules/suricata.rules", "r") as f:
    for line in f:
        match = re.search(r"metadata:([^;]+);", line)
        if match:
            pairs = match.group(1).split(", ")
            for pair in pairs:
                key, value = pair.split(" ", 1)
                if key not in metadata_dict:
                    metadata_dict[key] = set()
                metadata_dict[key].add(value)
for key, values in metadata_dict.items():
    print(f"{key}: {', '.join(values)}")