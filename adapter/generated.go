package adapter

func GomlBind_hmac_key(p0 []uint8, p1 string) (Key, string) {
    return HMACKey(p0, p1)
}

func GomlBind_key_algorithm(p0 Key) string {
    return KeyAlgorithm(p0)
}

func GomlBind_key_id(p0 Key) string {
    return KeyID(p0)
}

func GomlBind_now() int64 {
    return Now()
}

func GomlBind_pem_key(p0 string, p1 string, p2 string, p3 bool) (Key, string) {
    return PEMKey(p0, p1, p2, p3)
}

func GomlBind_sign(p0 Key, p1 string, p2 string, p3 int) (string, string) {
    return Sign(p0, p1, p2, p3)
}

func GomlBind_verify(p0 []Key, p1 string, p2 []string, p3 string, p4 string, p5 string, p6 int64, p7 int64, p8 bool, p9 bool, p10 int) (string, string, string) {
    return Verify(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)
}
