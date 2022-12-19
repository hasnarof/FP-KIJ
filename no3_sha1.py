import struct

class SHA1Hash:
    
    def __init__(self) -> None:
        pass
    
    def circularLeftShift(self, x, n):
        # x << n adalah left-shift operation
        # x >> (32 - n ) adalah right shift operation
        # jika di OR kan akan menghasilkan circular left shift operation
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    def calculateW(self, block):
        # dibutuhkan 16 word, word 1 - 16 diambil dari 16 word pada blok yang sedang diproses (1 word = 32 bit).
        # sementara untuk word diatas 16 ada rumusnya sendiri
        w = list(struct.unpack(">16L", block)) + [0] * 64
        for i in range(16, 80):
            w[i] = self.circularLeftShift((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
        return w
        
    def mainHash(self, message):
        # 1. Penambahan bit-bit pengganjal
        """
        padding bits terdiri dari sebuah bit 1 dengan sisanya bit 0
        b\"x80" = 8 bit dengan awalan 1
        b\"x00" = 8 bit 0
        penambahan padding dilakukan agar panjang pesan kongruen dengan 448 (mod 512)
        
        kemudian, 0 bit sisanya berjumlah = 64 - 1 - 8 - panjang pesan
        64 = 512 bit
        1 = 8 bit di awal (b"\x80")
        8 = K, penambahan nilai panjang pesan dalam 64 bit di tahap no. 2
        """
        padding = b"\x80" + b"\x00" * (63 - (len(message) + 8) % 64)
        
        # 2. Penambahan nilai panjang pesan
        # K adalah nilai panjang pesan dalam 64 bit
        # setelah tahap ini panjang pesan menjadi kelipatan 512 bit
        K = struct.pack(">Q", 8 * len(message))
        
        
        padded_message = str.encode(message) + padding + K
        
        # 3. inisialisasi penyangga MD
        # Penyangga (buffer) yang disebut MD ini nantinya sebagai sebuah initial value
        md = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        
        # 4. Pengolahan pesan dalam blok berukuran 512 bit
        
        # 4a. pemecahan pesan menjadi blok-blok berukuran 512 bit
        blocks = []
        for i in range(0, len(padded_message), 64):
            blocks.append(padded_message[i : i + 64])
            
        # 4b. proses setiap blok       
        for block in blocks:
            # 4c. inisialisasi a, b, c, d, e dengan nilai penyangga md
            a, b, c, d, e = md
            # 4d. calculate W
            # W akan digunakan sebagai salah satu unsur perhitungan
            W = self.calculateW(block)
            
            # 4e. 80 ronde proses H_SHA
            for i in range(0, 80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                
                # 4f. pengisian value a, b, c, d, e pada tiap ronde H_SHA. Disini W[i] digunakan
                a, b, c, d, e = (
                    self.circularLeftShift(a, 5) + f + e + k + W[i] & 0xFFFFFFFF,
                    a,
                    self.circularLeftShift(b, 30),
                    c,
                    d
                )
            
            # 4g. setelah 80 ronde selesai, md lama ditambah dengan a, b, c, d, e dan diambil 8 bit terakhir
            md = (
                md[0] + a & 0xFFFFFFFF,
                md[1] + b & 0xFFFFFFFF,
                md[2] + c & 0xFFFFFFFF,
                md[3] + d & 0xFFFFFFFF,
                md[4] + e & 0xFFFFFFFF,
            )
        
        return "%08x%08x%08x%08x%08x" % tuple(md)

if __name__ == '__main__':
    print("Masukkan plaintext untuk hash SHA-1:")
    plaintext = input()
    
    sha1Hash = SHA1Hash()
    hashResult = sha1Hash.mainHash(plaintext)
    print(hashResult)