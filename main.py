import hashlib

n = 16
h = 66
d = 22
h_prime = 3
a = 6
lg_w = 4
m = 34

WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6

class ADRS:
    """
    바이트 배치:
        [ 0: 4]  LayerAddress  (4바이트)
        [ 4:16]  TreeAddress   (12바이트)
        [16:20]  type          (4바이트)
        [20:32]  addr          (12바이트)
    """

    SIZE = 32

    # 필드 이름: (시작 위치, 길이)
    _FIELDS = {
        "LayerAddress": (0, 4),
        "TreeAddress": (4, 12),
        "type": (16, 4),
        "addr": (20, 12),
    }

    def __init__(self, data=None):
        if data is None:
            self._buf = bytearray(self.SIZE)
        else:
            if len(data) != self.SIZE:
                raise ValueError(f"ADRS는 {self.SIZE}바이트여야 합니다 (받은 길이: {len(data)})")
            self._buf = bytearray(data)

    # ---- 내부 공통 함수 ----
    def _get(self, field):
        start, length = self._FIELDS[field]
        return int.from_bytes(self._buf[start:start + length], "big")

    def _set(self, field, value):
        start, length = self._FIELDS[field]
        if not 0 <= value < (1 << (8 * length)):
            raise ValueError(f"{field} 값이 {length}바이트 범위를 벗어났습니다: {value}")
        self._buf[start:start + length] = value.to_bytes(length, "big")

    # ---- 각 필드 getter / setter ----
    @property
    def LayerAddress(self):
        return self._get("LayerAddress")

    @LayerAddress.setter
    def LayerAddress(self, value):
        self._set("LayerAddress", value)

    @property
    def TreeAddress(self):
        return self._get("TreeAddress")

    @TreeAddress.setter
    def TreeAddress(self, value):
        self._set("TreeAddress", value)

    @property
    def type(self):
        return self._get("type")

    @type.setter
    def type(self, value):
        self._set("type", value)

    @property
    def addr(self):
        return self._get("addr")

    @addr.setter
    def addr(self, value):
        self._set("addr", value)

    # ---- 유틸리티 ----
    def to_bytes(self):
        """해시 함수 등에 넘길 32바이트 bytes 반환"""
        return bytes(self._buf)

    def copy(self):
        return ADRS(self._buf)

    def __len__(self):
        return self.SIZE

    def __repr__(self):
        return (f"ADRS(LayerAddress={self.LayerAddress}, TreeAddress={self.TreeAddress}, "
                f"type={self.type}, addr={self.addr})")

class PK:
    seed: bytes # n bytes
    root: bytes # n bytes

class SK:
    seed: bytes # n bytes
    prf : bytes # n bytes
    sk  : bytes # n bytes

def H_msg(R: bytes, PK_seed: bytes, PK_root: bytes, M: bytes, m: int) -> bytes:
    return hashlib.shake_256(R + PK_seed + PK_root + M).digest(m)

def PRF(PK_seed: bytes, SK_seed: bytes, ADRS: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS + SK_seed).digest(n)

def PRF_msg(SK_prf: bytes, opt_rand: bytes, M: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(SK_prf + opt_rand + M).digest(n)

def F(PK_seed: bytes, ADRS: bytes, M1: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS + M1).digest(n)

def H(PK_seed: bytes, ADRS: bytes, M2: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS + M2).digest(n)

def T_l(PK_seed: bytes, ADRS: bytes, Ml: bytes, n: int = 32) -> bytes:
    return hashlib.shake_256(PK_seed + ADRS + Ml).digest(n)

"""
함수 이름 : base_2b
설명 : 바이트 배열을 b진수로 변환하는 함수
입력 :
    X : 바이트 배열
    b : 변환할 진수 (2~8)
    out_len : 출력할 배열의 길이
출력 : b진수로 변환된 정수 배열
"""
def base_2b(X: bytes, b: int, out_len: int) -> list[int]:
    ArrNum, bits, total = 0, 0, 0
    baseb = []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + X[ArrNum]
            ArrNum += 1
            bits +=  8
        bits -= b
        baseb.append((total >> bits) & ((1 << b) - 1))
    return baseb

def chain(X: bytes, i: int, s: int, PK_seed: bytes, ADRS: bytes) -> bytes:
    for i in range(i + s):
        ADRS.setHashAddress(i)
        X = F(PK_seed, ADRS, tmp)
    return X

if __name__ == "__main__":
    a = ADRS()
    a.LayerAddress = 1
    a.TreeAddress = 0x0102030405
    a.type = 3
    a.addr = 0xABCDEF

    print(a)
    print("길이:", len(a.to_bytes()))
    raw = a.to_bytes().hex()
    print("hex :", " | ".join([raw[0:8], raw[8:32], raw[32:40], raw[40:64]]))
    print("base_2b:", base_2b(b'\x01\x02\x03\x04\x05\x06\x07\x08', 4, 16))