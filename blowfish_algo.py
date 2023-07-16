
from struct import Struct, error as struct_error
from itertools import cycle as iter_cycle
from Box import PI_P_ARRAY, PI_S_BOXES

class Cipher(object):
  
  def __init__(
    self, 
    key,
    byte_order_fmt = ">",
    P_array = PI_P_ARRAY,
    S_boxes = PI_S_BOXES
  ):
    if not 4 <= len(key) <= 56:
      raise ValueError("key is not between 4 and 56 bytes")
    
    if not len(P_array) or len(P_array) % 2 != 0:
      raise ValueError("P array is not an even length sequence")
    
    if len(S_boxes) != 4 or any(len(box) != 256 for box in S_boxes):
      raise ValueError("S-boxes is not a 4 x 256 sequence")
      
    self.byte_order_fmt = byte_order_fmt
    
    # Create structs
    u4_2_struct = Struct("{}2I".format(byte_order_fmt)) #một cặp (pair) của hai số nguyên 32-bit (4 byte)
    u4_1_struct = Struct(">I".format(byte_order_fmt)) # một số nguyên 32-bit (4 byte) 
    u8_1_struct = Struct("{}Q".format(byte_order_fmt)) #một số nguyên 64-bit (8 byte)
    u1_4_struct = Struct("=4B") #một tuple gồm 4 byte (32-bit) 
      
    # Save refs locally to the needed pack/unpack funcs of the structs to speed
    # up look-ups a little.
    self._u4_2_pack = u4_2_struct.pack #đóng gói hai giá trị số nguyên 32-bit thành một chuỗi bytes
    self._u4_2_unpack = u4_2_struct.unpack # một chuỗi 4 bytes thành hai giá trị số nguyên 32-bit
    self._u4_2_iter_unpack = u4_2_struct.iter_unpack # sử dụng trong vòng lặp 
    
    self._u4_1_pack  = u4_1_struct.pack # đóng gói một giá trị số nguyên 32-bit thành một chuỗi 4 bytes
    
    self._u1_4_unpack = u1_4_struct.unpack #một chuỗi 1 bytes thành bốn giá trị số nguyên 8-bit
    
    self._u8_1_pack = u8_1_struct.pack #đóng gói một giá trị số nguyên 64-bit thành một chuỗi 8 bytes
    
    # Cyclic key iterator: lặp vô hạn lần lại chuỗi key
    cyclic_key_iter = iter_cycle(iter(key))
    
    # Cyclic 32-bit integer iterator over key bytes 
    # một đối tượng generator, 
    # và khi yêu cầu giá trị từ đối tượng này, nó sẽ trả về các giá trị số nguyên 32-bit từ chuỗi byte key, 
    # được tạo ra bằng cách lặp lại các giá trị của key theo từng cặp giá trị 32-bit.
    cyclic_key_u4_iter = (
      x for (x,) in map(
        u4_1_struct.unpack,
        map(
          bytes,
          zip(
            cyclic_key_iter,
            cyclic_key_iter,
            cyclic_key_iter,
            cyclic_key_iter
          )
        )
      )
    )
        
    # Create and initialize subkey P array 
    
    # XOR each element in P_array with key and save as pairs.// gồm 9 cặp khóa phụ 
    P = [
      (p1 ^ k1, p2 ^ k2) for p1, p2, k1, k2 in zip(
        P_array[0::2],
        P_array[1::2],
        cyclic_key_u4_iter,
        cyclic_key_u4_iter
      )
    ]
    
    # Save P as a tuple since working with tuples is slightly faster
    self.P = P = tuple(P)
    
    # Save S
    S = [[x for x in box] for box in S_boxes]
    self.S = tuple(tuple(box) for box in S)
    
  @staticmethod
  def _encrypt(L, R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack):
    for p1, p2 in P[:-1]:
      #vong lap thu 1
      L ^= p1
      #tim chi so cac s_box
      a, b, c, d = u1_4_unpack(u4_1_pack(L))
      R ^= ((S1[a] + S2[b] ^ S3[c]) + S4[d]) % 2**32
      #vong lap thu 2
      R ^= p2
      a, b, c, d = u1_4_unpack(u4_1_pack(R))
      L ^= ((S1[a] + S2[b] ^ S3[c]) + S4[d]) % 2**32
    p_16, p_17 = P[-1]
    return R ^ p_17, L ^ p_16
  
  @staticmethod
  def _decrypt(L, R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack):
    for p2, p1 in P[:0:-1]:
      L = p1^L
      a, b, c, d = u1_4_unpack(u4_1_pack(L))
      R ^= ((S1[a] + S2[b] ^ S3[c]) + S4[d]) % 2**32
      R ^= p2
      a, b, c, d = u1_4_unpack(u4_1_pack(R))
      L ^= ((S1[a] + S2[b] ^ S3[c]) + S4[d]) % 2**32
    p_0, p_1 = P[0]
    return R ^ p_0, L ^ p_1
  
  ##### mã hóa khối với chế độ ecb và cts
  def encrypt_ecb_cts(self, data):

    data_len = len(data)
    if data_len <= 8:
      raise ValueError("data is not greater than 8 bytes in length")
      
    S1, S2, S3, S4 = self.S
    P = self.P
    
    u4_1_pack = self._u4_1_pack
    u1_4_unpack = self._u1_4_unpack
    u4_2_pack = self._u4_2_pack
    u4_2_unpack = self._u4_2_unpack
    encrypt = self._encrypt
    
    extra_bytes = data_len % 8
    last_block_stop_i = data_len - extra_bytes
    
    plain_L, plain_R = u4_2_unpack(data[0:8])
    cipher_block = u4_2_pack(
      *encrypt(plain_L, plain_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
    )
    
    for plain_L, plain_R in self._u4_2_iter_unpack(data[8:last_block_stop_i]):
      yield cipher_block
      cipher_block = u4_2_pack(
        *encrypt(plain_L, plain_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
      )
    
    #khối cuối được tạo từ phần plain text thừa và thêm các byte còn thiếu lấy từ cipher text 
    plain_L, plain_R = u4_2_unpack(
      data[last_block_stop_i:] + cipher_block[extra_bytes:]
    )
    
    yield u4_2_pack(
      *encrypt(plain_L, plain_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
    )
    yield cipher_block[:extra_bytes]
  
  ###### mã hóa khối với chế độ ecb và cts
  def decrypt_ecb_cts(self, data):
    
    data_len = len(data)
    if data_len <= 8:
      raise ValueError("data is not greater than 8 bytes in length")
      
    S1, S2, S3, S4 = self.S
    P = self.P
    
    u4_1_pack = self._u4_1_pack
    u1_4_unpack = self._u1_4_unpack
    u4_2_pack = self._u4_2_pack
    u4_2_unpack = self._u4_2_unpack
    decrypt = self._decrypt
    
    extra_bytes = data_len % 8
    last_block_stop_i = data_len - extra_bytes
        
    cipher_L, cipher_R = u4_2_unpack(data[0:8])
    plain_block = u4_2_pack(
      *decrypt(cipher_L, cipher_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
    )
    
    for cipher_L, cipher_R in self._u4_2_iter_unpack(data[8:last_block_stop_i]):
      yield plain_block
      plain_block = u4_2_pack(
        *decrypt(cipher_L, cipher_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
      )
    
    cipher_L, cipher_R = u4_2_unpack(
      data[last_block_stop_i:] + plain_block[extra_bytes:]
    )
    
    yield u4_2_pack(
      *decrypt(cipher_L, cipher_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
    )
    yield plain_block[:extra_bytes]
    

if __name__ == "__main__":
    cipher = Cipher(b"admin_key")
    data = b"aaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa"
    encrypted_blocks = cipher.encrypt_ecb_cts(data)

    for block in encrypted_blocks:

        print(block)
