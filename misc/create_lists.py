def extract_hex_codes(filename):
    hex_codes = []

    with open(filename, 'r') as file:
        for line in file:
            if line.startswith("Header content (hex):"):
                parts = line.split()
                if parts:
                    hex_code = parts[-1]
                    hex_codes.append(hex_code)

            if line.startswith("K content (hex):"):
                parts = line.split()
                if parts:
                    hex_code = parts[-1]
                    K = hex_code
    
    return hex_codes, K

def format_hex_codes(hex_codes):
    formatted_list = "headers = [" + ", ".join(f"'{code}'" for code in hex_codes) + "]"
    return formatted_list

def main():
    filename = 'arc4_test_data.txt'
    # filename = '../arc4_test_client_data.txt'
    hex_codes, K = extract_hex_codes(filename)

    formatted_list = format_hex_codes(hex_codes)
    print(formatted_list)
    print(f'K = "{K}"')

if __name__ == "__main__":
    main()


