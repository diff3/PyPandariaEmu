#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

from dataclasses import dataclass
import struct
import hashlib
from utils.Logger import Logger


class HandleProof:

    @staticmethod
    def check_proof():
        _login = "MAPE"

        # From Server
        N_hex = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
        s_hex = "DCCB88FE78D06F584597861AF39CDFEE0D4FD5EFB2961615E99FAEAB0AA16B93"
        v_hex = "5CFB50BF6DD9D76C56A2F72709C1DE7E0683C12E84EF552720E3CAF640384F5A"
        g = 7
        b_hex = "979CD6A6747EDA0BFDF842375339ADA421CBC1"
        B_hex = "1C1E4E89E120A72E70DDDF9F284A9B5B82BDC84CDB9A946E57FFB2D4B680B0D5"

        # From Client
        M1 = "96D24591134E93022EA008AF8CA97BC0A4D4CBF9"
        A_hex = "4112BBD86EB34C245EE0C9495F841E3CB34829B8F31291BB3E314B765C9304BB"

        # Sample 1
        M1 = "0D450921F79BEF921DC7A72F6169F3AB26169A97"
        A_hex = "22B71E6BF41D0F877C137E1FACFA1AA02A2D8574C85E44925CF346AE397DEA96"


        N = int(N_hex, 16)
        v = int(v_hex, 16)
        b = int(b_hex, 16)
        s = int(s_hex, 16)

        B = int(B_hex, 16)
        A = int(A_hex, 16)

        # print(f'B={B}')
        # print(f'A={A}')

        

        sha1 = hashlib.sha1()
        sha1.update(A.to_bytes((A.bit_length() + 7) // 8, 'little'))
        sha1.update(B.to_bytes((B.bit_length() + 7) // 8, 'little'))     
        u = int.from_bytes(sha1.digest(), byteorder='little')

        print(f'A={A.to_bytes((A.bit_length() + 7) // 8, 'big').hex().upper()}') # Korrekt
        print(f'B={B.to_bytes((B.bit_length() + 7) // 8, 'big').hex().upper()}') # Korrekt
        print(f'u={u.to_bytes((u.bit_length() + 7) // 8, 'big').hex().upper()}') # Korrekt

        S = pow(A * pow(v, u, N), b, N)
        print(f'S={S.to_bytes((S.bit_length() + 7) // 8, 'big').hex().upper()}') # Korrekt

        t = bytearray(32)  
        t1 = bytearray(16)  
        vK = bytearray(40) 

        t = S.to_bytes(32, byteorder='big') 
        print(f't={t.hex()}') # korrekt

        for i in range(16):
            t1[i] = t[i * 2 + 1]

        print(f't1 (1)={t1.hex().upper()}') # Fungerar

        sha1 = hashlib.sha1()
        sha1.update(t1)
        digest = sha1.digest()

        for i in range(20):
            vK[i * 2] = digest[i]

        print(f'vK (1)={vK.hex()}') # Nej

        for i in range(16):
            t1[i] = t[i * 2]

        print(f't1 (2)={t1.hex()}') # Fungerar

        sha1 = hashlib.sha1()
        sha1.update(t1[:16])
        digest = sha1.digest()

        for i in range(20):
            vK[i * 2 + 1] = digest[i]

        print(f'vK (2)={vK.hex()}') # Nej

        K = int.from_bytes(vK, byteorder='little')
        

        K = int("4EBAF24603240C5BE219534324744D5A3B4BD58CE3A9992071B4D4BA1CC3E7C744C000021FD745B0", 16)
        print(f'K={K.to_bytes((K.bit_length() + 7) // 8, 'big').hex().upper()}') 


        sha1 = hashlib.sha1()
        sha1.update(N.to_bytes((N.bit_length() + 7) // 8, 'little'))
        hash = bytearray(sha1.digest())[::-1]

        print(hash.hex()) # fungerar

        sha1 = hashlib.sha1()
        sha1.update(g.to_bytes((g.bit_length() + 7) // 8, 'big'))
        digest = sha1.digest()

        for i in range(20):
            hash[i] ^= digest[i]

        print(hash.hex()) 

        t3 = int.from_bytes(hash, byteorder='big')
        print(f't3={t3.to_bytes((t3.bit_length() + 7) // 8, 'big').hex().upper()}') # Korrekt

        sha1 = hashlib.sha1()
        sha1.update(_login.encode('utf-8'))
        t4 = int(sha1.digest().hex(), 16)

        print(f't4={t4.to_bytes((t4.bit_length() + 7) // 8, 'little').hex().upper()}') # Korrekt
        print(f's={s.to_bytes((s.bit_length() + 7) // 8, 'big').hex().upper()}') # Korrekt

        sha1 = hashlib.sha1()
        sha1.update(t3.to_bytes((t3.bit_length() + 7) // 8, 'big')) # rätt
        sha1.update(t4.to_bytes((t4.bit_length() + 7) // 8, 'little')) # rätt
        sha1.update(s.to_bytes((s.bit_length() + 7) // 8, 'big')) # rätt
        sha1.update(A.to_bytes((A.bit_length() + 7) // 8, 'big')) # rätt
        sha1.update(B.to_bytes((B.bit_length() + 7) // 8, 'big')) # rätt
        sha1.update(K.to_bytes((K.bit_length() + 7) // 8, 'big'))
        M = sha1.digest()[::-1]
        
        print(f'M   ={M.hex().upper()}')
        print(f'M1  ={M1}')

        if M.hex().upper() == M1:
            print("Found key")


        # Lista med alla möjliga byteordningar
        byte_orders = ['little', 'big']

        # Generera alla kombinationer av byteordningar
        for order_t3 in byte_orders:
            for order_t4 in byte_orders:
                for order_s in byte_orders:
                    for order_A in byte_orders:
                        for order_B in byte_orders:
                            for order_K in byte_orders:
                                sha1 = hashlib.sha1()
                                sha1.update(t3.to_bytes((t3.bit_length() + 7) // 8, order_t3))
                                sha1.update(t4.to_bytes((t4.bit_length() + 7) // 8, order_t4))
                                sha1.update(s.to_bytes((s.bit_length() + 7) // 8, order_s))
                                sha1.update(A.to_bytes((A.bit_length() + 7) // 8, order_A))
                                sha1.update(B.to_bytes((B.bit_length() + 7) // 8, order_B))
                                sha1.update(K.to_bytes((K.bit_length() + 7) // 8, order_K))
                                M = sha1.digest()
                                
                                if M.hex().upper() == M1:
                                    print("Found key")


                                    print(f"Combination: t3={order_t3}, t4={order_t4}, s={order_s}, A={order_A}, B={order_B}, K={order_K}")
                                    print(f"M={M.hex().upper()}")
                                    print()


if __name__ == "__main__":
    HandleProof.check_proof()