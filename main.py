import os
from sensorInfo import main as get_curl_command

def update_yaml(template_path="salttemplate.sh", output_path="saltinstall.sh"):
    """Replace the #CURL_COMMAND_GOES_HERE placeholder in the YAML file with the indented curl command."""
    # Get the curl command
    try:
        curl_command = get_curl_command()
    except Exception as e:
        raise RuntimeError(f"Failed to generate curl command: {e}")

    # Read the template
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"{template_path} not found")

    with open(template_path, 'r') as f:
        lines = f.readlines()

    # Find and replace the placeholder
    new_lines = []
    found_placeholder = False
    skip_next_curl = False
    indent = "          "  # 10 spaces to match UserData script indentation

    for line in lines:
        if '#CURL_COMMAND_GOES_HERE' in line:
            found_placeholder = True
            new_lines.append(line.rstrip('\n') + '\n')  # Keep the placeholder
            new_lines.append(f"{indent}{curl_command}\n")  # Add indented curl command
            skip_next_curl = True
        elif skip_next_curl and line.strip().startswith('curl'):
            continue  # Skip existing curl command
        else:
            new_lines.append(line)
            skip_next_curl = False

    if not found_placeholder:
        raise ValueError("Placeholder #CURL_COMMAND_GOES_HERE not found in template")

    # Write the updated template
    with open(output_path, 'w') as f:
        f.writelines(new_lines)

    print(f"Updated template written to {output_path}")

if __name__ == "__main__":
    try:
        update_yaml()
    except Exception as e:
        print(f"Error: {e}")

