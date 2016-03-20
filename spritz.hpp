#ifndef _SPRITZ_HEADER
#define _SPRITZ_HEADER 1

#include <vector>

typedef unsigned char byte;
typedef std::vector<byte> ByteArray;

class Spritz {
public:
    static void crypt(ByteArray &data, ByteArray key, ByteArray iv = ByteArray());

    static ByteArray hash(ByteArray data, int bits);

    static ByteArray mac(ByteArray data, ByteArray key, int bits);

private:
    int i = 0, j = 0, k = 0, z = 0, a = 0, w = 1;
    byte s[256];

    Spritz();

    void swap(int a, int b);

    void absorb(ByteArray i);

    void absorbByte(byte b);

    void absorbNibble(int x);

    void absorbStop();

    void shuffle();

    void whip(int r);

    void crush();

    ByteArray squeeze(size_t r);

    byte drip();

    void update();

    byte output();
};

#endif /* _SPRITZ_HEADER */