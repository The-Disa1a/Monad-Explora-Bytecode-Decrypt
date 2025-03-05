import re
import json
import requests

# Function to extract 4-byte selectors from bytecode
def extract_function_selectors(bytecode):
    selectors = re.findall(r"63([a-fA-F0-9]{8})", bytecode)
    return list(set(selectors))  # Remove duplicates

# Function to fetch function signatures from 4byte.directory
def fetch_function_signatures(selectors):
    abi_methods = []
    for selector in selectors:
        url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{selector}"
        response = requests.get(url).json()
        
        if response["count"] > 0:
            function_name = response["results"][0]["text_signature"]
            abi_methods.append({
                "type": "function",
                "name": function_name.split("(")[0],
                "inputs": [
                    {"type": param, "name": f"param{i}"} 
                    for i, param in enumerate(function_name.split("(")[1][:-1].split(",")) if param
                ],
                "outputs": [],
                "stateMutability": "nonpayable"  # Default, can be improved later
            })
    
    return abi_methods

# Main function to generate ABI
def generate_abi(bytecode):
    selectors = extract_function_selectors(bytecode)
    abi_methods = fetch_function_signatures(selectors)
    
    abi_json = json.dumps(abi_methods, indent=4)
    return abi_json

# Example usage
if __name__ == "__main__":
    bytecode = input("Enter contract bytecode: ").strip()
    abi_result = generate_abi(bytecode)
    print("\nExtracted ABI JSON:\n", abi_result)
