import struct

data = b'\x00\x00\x00\x00Pandaria\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x01\x01\x01\x10\x00'
data = b'\x10.\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02Pandaria\x00192.168.11.30:8085\x00\x00\x00@@\x01\x01\x01\x10\x00'

def unpack_realm_data(data):
    # Unpack the fixed-size fields
    realm_icon, lock, flag = struct.unpack('HBB', data[:4])
    
    # Find the null-terminated strings for name and address
    rest_data = data[4:]

    name_end = rest_data.find(b'\x00')
    name = rest_data[:name_end].decode('utf-8')

    rest_data = rest_data[name_end + 1:]

    address_end = rest_data.find(b'\x00')
    address = rest_data[:address_end].decode('utf-8')
    
    rest_data = rest_data[address_end + 1:]

    print(rest_data)
    print(len(rest_data))

    # Unpack the remaining fields
  #  population_level, amount_of_characters, timezone, major_version, minor_version, bugfix_version, build = struct.unpack('IIIIIIIIIIBBB', rest_data)
    
    return {
        'Realm Icon': realm_icon,
        'Flag': flag,
        'Name': name,
        'Address': address,
   #     'Population Level': population_level,
    #    'Amount of Characters': amount_of_characters,
     #   'Timezone': timezone,
    #    'Build Info': {
    #        'Major': major_version,
    #        'Minor': minor_version,
    #        'Bugfix': bugfix_version,
    #        'Build': build
    #    }
    }

# Test the function
realm_info = unpack_realm_data(data)
for key, value in realm_info.items():
    if isinstance(value, dict):
        print(f'{key}:')
        for sub_key, sub_value in value.items():
            print(f'  {sub_key}: {sub_value}')
    else:
        print(f'{key}: {value}')
